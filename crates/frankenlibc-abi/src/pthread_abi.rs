//! ABI layer for selected `<pthread.h>` functions.
//!
//! This bootstrap implementation provides runtime-math routed threading surfaces
//! while full POSIX pthread coverage is still in progress.

#![allow(clippy::missing_safety_doc)]

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, c_int, c_void};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};

use frankenlibc_core::elf::Elf64Header;
use frankenlibc_core::elf::section::{SectionType, parse_section_headers};
use frankenlibc_core::elf::symbol::{get_string, parse_symbols};
use frankenlibc_core::pthread::tls::{
    PthreadKey, pthread_key_create as core_pthread_key_create,
    pthread_key_delete as core_pthread_key_delete,
};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use frankenlibc_core::pthread::tls::{
    pthread_getspecific as core_pthread_getspecific,
    pthread_setspecific as core_pthread_setspecific,
};
use frankenlibc_core::pthread::{
    CondvarData, MANAGED_CONDVAR_MAGIC, PTHREAD_COND_CLOCK_MONOTONIC, PTHREAD_COND_CLOCK_REALTIME,
    THREAD_DETACHED, THREAD_FINISHED, THREAD_JOINED, ThreadHandle,
    condvar_broadcast as core_condvar_broadcast, condvar_destroy as core_condvar_destroy,
    condvar_init as core_condvar_init, condvar_signal as core_condvar_signal,
    condvar_timedwait as core_condvar_timedwait, condvar_wait as core_condvar_wait,
    create_thread as core_create_thread, detach_thread as core_detach_thread,
    exit_current_thread as core_exit_current_thread, handle_for_tid as core_handle_for_tid,
    join_thread as core_join_thread, self_tid as core_self_tid,
};
use frankenlibc_core::syscall::{
    syscall_result, syscall0, syscall1, syscall2, syscall3, syscall4, syscall5,
};
use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::runtime_math::ApiFamily;

use crate::errno_abi::set_abi_errno;
use crate::htm_fast_path::{HtmSite, HtmSiteSnapshot};
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
type HostPthreadGetattrFn =
    unsafe extern "C" fn(libc::pthread_t, *mut libc::pthread_attr_t) -> c_int;
type HostPthreadKeyCreateFn = unsafe extern "C" fn(
    *mut libc::pthread_key_t,
    Option<unsafe extern "C" fn(*mut c_void)>,
) -> c_int;
type HostPthreadKeyDeleteFn = unsafe extern "C" fn(libc::pthread_key_t) -> c_int;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
type HostPthreadGetspecificFn = unsafe extern "C" fn(libc::pthread_key_t) -> *mut c_void;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
type HostPthreadSetspecificFn = unsafe extern "C" fn(libc::pthread_key_t, *const c_void) -> c_int;
type HostPthreadMutexInitFn =
    unsafe extern "C" fn(*mut libc::pthread_mutex_t, *const libc::pthread_mutexattr_t) -> c_int;
type HostPthreadMutexDestroyFn = unsafe extern "C" fn(*mut libc::pthread_mutex_t) -> c_int;
type HostPthreadMutexLockFn = unsafe extern "C" fn(*mut libc::pthread_mutex_t) -> c_int;
type HostPthreadMutexTimedlockFn =
    unsafe extern "C" fn(*mut libc::pthread_mutex_t, *const libc::timespec) -> c_int;
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
type HostPthreadCondattrGetclockFn =
    unsafe extern "C" fn(*const libc::pthread_condattr_t, *mut libc::clockid_t) -> c_int;
type HostPthreadMutexattrInitFn = unsafe extern "C" fn(*mut libc::pthread_mutexattr_t) -> c_int;
type HostPthreadMutexattrDestroyFn = unsafe extern "C" fn(*mut libc::pthread_mutexattr_t) -> c_int;
type HostPthreadMutexattrSettypeFn =
    unsafe extern "C" fn(*mut libc::pthread_mutexattr_t, c_int) -> c_int;
type HostPthreadMutexattrGettypeFn =
    unsafe extern "C" fn(*const libc::pthread_mutexattr_t, *mut c_int) -> c_int;
type HostPthreadMutexattrSetprotocolFn =
    unsafe extern "C" fn(*mut libc::pthread_mutexattr_t, c_int) -> c_int;
type HostPthreadMutexattrGetprotocolFn =
    unsafe extern "C" fn(*const libc::pthread_mutexattr_t, *mut c_int) -> c_int;
type HostPthreadMutexattrSetpsharedFn =
    unsafe extern "C" fn(*mut libc::pthread_mutexattr_t, c_int) -> c_int;
type HostPthreadMutexattrGetpsharedFn =
    unsafe extern "C" fn(*const libc::pthread_mutexattr_t, *mut c_int) -> c_int;
type HostPthreadMutexattrSetrobustFn =
    unsafe extern "C" fn(*mut libc::pthread_mutexattr_t, c_int) -> c_int;
type HostPthreadMutexattrGetrobustFn =
    unsafe extern "C" fn(*const libc::pthread_mutexattr_t, *mut c_int) -> c_int;
type ResolvedPthreadAttrInitFn = unsafe extern "C" fn(*mut libc::pthread_attr_t) -> c_int;
type ResolvedPthreadAttrDestroyFn = unsafe extern "C" fn(*mut libc::pthread_attr_t) -> c_int;
type ResolvedPthreadAttrSetdetachstateFn =
    unsafe extern "C" fn(*mut libc::pthread_attr_t, c_int) -> c_int;
type ResolvedPthreadAttrGetdetachstateFn =
    unsafe extern "C" fn(*const libc::pthread_attr_t, *mut c_int) -> c_int;
type ResolvedPthreadAttrSetguardsizeFn =
    unsafe extern "C" fn(*mut libc::pthread_attr_t, usize) -> c_int;
type ResolvedPthreadAttrGetguardsizeFn =
    unsafe extern "C" fn(*const libc::pthread_attr_t, *mut usize) -> c_int;
type ResolvedPthreadAttrSetstackFn =
    unsafe extern "C" fn(*mut libc::pthread_attr_t, *mut c_void, usize) -> c_int;
type ResolvedPthreadAttrGetstackFn = unsafe extern "C" fn(
    *const libc::pthread_attr_t,
    *mut *mut c_void,
    *mut usize,
) -> c_int;
type ResolvedPthreadAttrSetstacksizeFn =
    unsafe extern "C" fn(*mut libc::pthread_attr_t, usize) -> c_int;
type ResolvedPthreadAttrGetstacksizeFn =
    unsafe extern "C" fn(*const libc::pthread_attr_t, *mut usize) -> c_int;
type ResolvedPthreadAttrSetinheritschedFn =
    unsafe extern "C" fn(*mut libc::pthread_attr_t, c_int) -> c_int;
type ResolvedPthreadAttrGetinheritschedFn =
    unsafe extern "C" fn(*const libc::pthread_attr_t, *mut c_int) -> c_int;
type ResolvedPthreadAttrSetschedpolicyFn =
    unsafe extern "C" fn(*mut libc::pthread_attr_t, c_int) -> c_int;
type ResolvedPthreadAttrGetschedpolicyFn =
    unsafe extern "C" fn(*const libc::pthread_attr_t, *mut c_int) -> c_int;
type ResolvedPthreadAttrSetschedparamFn =
    unsafe extern "C" fn(*mut libc::pthread_attr_t, *const libc::sched_param) -> c_int;
type ResolvedPthreadAttrGetschedparamFn =
    unsafe extern "C" fn(*const libc::pthread_attr_t, *mut libc::sched_param) -> c_int;
type ResolvedPthreadAttrSetaffinityNpFn =
    unsafe extern "C" fn(*mut libc::pthread_attr_t, usize, *const libc::cpu_set_t) -> c_int;
type ResolvedPthreadAttrSetsigmaskNpFn =
    unsafe extern "C" fn(*mut libc::pthread_attr_t, *const libc::sigset_t) -> c_int;
// Host attr type aliases reintroduced for LD_PRELOAD compatibility in host mode.

// ---------------------------------------------------------------------------
// Futex-backed NORMAL mutex core (bd-z84)
// ---------------------------------------------------------------------------

static MUTEX_SPIN_BRANCHES: AtomicU64 = AtomicU64::new(0);
static MUTEX_WAIT_BRANCHES: AtomicU64 = AtomicU64::new(0);
static MUTEX_WAKE_BRANCHES: AtomicU64 = AtomicU64::new(0);
static PTHREAD_CONCURRENCY_LEVEL: AtomicI32 = AtomicI32::new(0);
#[allow(dead_code)]
static PTHREAD_MUTEX_HTM_SITE: HtmSite = HtmSite::new("pthread_mutex_lock");

/// When true, mutex operations skip host delegation and use the native futex
/// implementation directly. Set by [`pthread_mutex_reset_state_for_tests`] so
/// that tests can exercise the futex state machine without glibc intercepting.
// NOTE: Kept false to prefer host delegation for mutex/condvar operations.
// Host delegation is essential for compatibility with programs that depend
// on glibc's pthread internals (Python GIL, Node.js libuv, etc.).
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
const MUTEX_MAGIC_OFFSET: usize = std::mem::size_of::<AtomicI32>();
const MUTEX_TYPE_OFFSET: usize = MUTEX_MAGIC_OFFSET + std::mem::size_of::<AtomicU32>();
const MUTEX_OWNER_OFFSET: usize = MUTEX_TYPE_OFFSET + std::mem::size_of::<AtomicI32>();
const MUTEX_LOCK_COUNT_OFFSET: usize = MUTEX_OWNER_OFFSET + std::mem::size_of::<AtomicI32>();
const RWLOCK_MAGIC_OFFSET: usize = std::mem::size_of::<AtomicI32>();

struct ManagedThreadRecord {
    handle_raw: usize,
    stack_size: usize,
    detach_state: c_int,
}

static THREAD_HANDLE_REGISTRY: LazyLock<Mutex<HashMap<usize, ManagedThreadRecord>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static MANAGED_THREAD_TOMBSTONES: LazyLock<Mutex<HashSet<usize>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));
static DETACHED_THREAD_TOMBSTONES: LazyLock<Mutex<HashSet<usize>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));
static DETACHED_THREAD_TID_SNAPSHOTS: LazyLock<Mutex<HashMap<usize, i32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static CANCEL_PENDING_REGISTRY: LazyLock<Mutex<HashMap<usize, bool>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static HOST_SYMBOL_CACHE: LazyLock<Mutex<HashMap<&'static [u8], usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static HOST_LIBC_SYMBOL_CACHE: LazyLock<Mutex<HashMap<&'static str, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static HOST_LIBC_HANDLE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static HOST_PTHREAD_CREATE_PTR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static HOST_PTHREAD_JOIN_PTR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static HOST_PTHREAD_DETACH_PTR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static HOST_PTHREAD_SELF_PTR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static HOST_PTHREAD_EQUAL_PTR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static HOST_PTHREAD_CONDATTR_GETCLOCK_PTR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static RESOLVED_PTHREAD_ATTR_INIT_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_DESTROY_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_SETDETACHSTATE_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_GETDETACHSTATE_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_SETGUARDSIZE_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_GETGUARDSIZE_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_SETSTACK_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_GETSTACK_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_SETSTACKSIZE_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_GETSTACKSIZE_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_SETINHERITSCHED_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_GETINHERITSCHED_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_SETSCHEDPOLICY_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_GETSCHEDPOLICY_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_SETSCHEDPARAM_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_GETSCHEDPARAM_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_SETAFFINITY_NP_PTR: OnceLock<usize> = OnceLock::new();
static RESOLVED_PTHREAD_ATTR_SETSIGMASK_NP_PTR: OnceLock<usize> = OnceLock::new();
static HOST_PTHREAD_KEY_CREATE_PTR: OnceLock<usize> = OnceLock::new();
static HOST_PTHREAD_KEY_DELETE_PTR: OnceLock<usize> = OnceLock::new();
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
static HOST_PTHREAD_GETSPECIFIC_PTR: OnceLock<usize> = OnceLock::new();
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
static HOST_PTHREAD_SETSPECIFIC_PTR: OnceLock<usize> = OnceLock::new();

thread_local! {
    static FORCE_NATIVE_THREADING_OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
    static THREADING_POLICY_DEPTH: Cell<u32> = const { Cell::new(0) };
    static THREAD_CANCEL_STATE: Cell<c_int> = const { Cell::new(PTHREAD_CANCEL_ENABLE_STATE) };
    static THREAD_CANCEL_TYPE: Cell<c_int> = const { Cell::new(PTHREAD_CANCEL_DEFERRED_TYPE) };
    static CURRENT_THREADING_BACKEND: Cell<u8> = const { Cell::new(THREAD_BACKEND_UNKNOWN) };
    static CURRENT_PTHREAD_SELF_CACHE: Cell<libc::pthread_t> = const { Cell::new(0) };
}

#[inline]
fn force_native_threading_enabled() -> bool {
    FORCE_NATIVE_THREADING_OVERRIDE.with(|override_cell| {
        override_cell
            .get()
            .unwrap_or_else(|| FORCE_NATIVE_THREADING.load(Ordering::Acquire))
    })
}

const THREAD_BACKEND_UNKNOWN: u8 = 0;
const THREAD_BACKEND_MANAGED: u8 = 1;
const THREAD_BACKEND_HOST: u8 = 2;

#[inline]
fn current_threading_backend() -> u8 {
    if force_native_threading_enabled() {
        return THREAD_BACKEND_MANAGED;
    }

    CURRENT_THREADING_BACKEND
        .try_with(|backend| {
            let cached = backend.get();
            if cached != THREAD_BACKEND_UNKNOWN {
                return cached;
            }

            let resolved = match core_self_tid() {
                tid if tid > 0 && core_handle_for_tid(tid).is_some() => THREAD_BACKEND_MANAGED,
                _ => {
                    if crate::host_resolve::host_pthread_self_raw().is_some() {
                        THREAD_BACKEND_HOST
                    } else {
                        THREAD_BACKEND_MANAGED
                    }
                }
            };
            backend.set(resolved);
            resolved
        })
        .unwrap_or(THREAD_BACKEND_MANAGED)
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
    // SAFETY: the symbol name is a static NUL-terminated C string.
    let resolved = unsafe { resolve_host_symbol_nocache(name) };
    if !resolved.is_null() {
        HOST_SYMBOL_CACHE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name, resolved as usize);
    }
    resolved
}

fn loaded_libc_base_and_path() -> Option<(u64, String)> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let _perms = parts.next()?;
        let offset = parts.next()?;
        let _dev = parts.next()?;
        let _inode = parts.next()?;
        let path = parts.next()?;
        if !path.contains("libc.so.6") {
            continue;
        }
        let mut range_parts = range.split('-');
        let start = u64::from_str_radix(range_parts.next()?, 16).ok()?;
        let file_offset = u64::from_str_radix(offset, 16).ok()?;
        return Some((start.saturating_sub(file_offset), path.to_string()));
    }
    None
}

fn resolve_loaded_libc_symbol_direct(symbol: &'static str) -> Option<usize> {
    if let Some(addr) = HOST_LIBC_SYMBOL_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(symbol)
        .copied()
    {
        return (addr != 0).then_some(addr);
    }

    let (base, path) = loaded_libc_base_and_path()?;
    let data = std::fs::read(path).ok()?;
    let header = Elf64Header::parse(&data).ok()?;
    let sections =
        parse_section_headers(&data, header.e_shoff, header.e_shentsize, header.e_shnum).ok()?;
    let dynsym_section = sections
        .iter()
        .find(|section| matches!(section.sh_type, SectionType::Dynsym))?;
    let dynstr_section = sections.get(dynsym_section.sh_link as usize)?;
    let dynstr_start = dynstr_section.sh_offset as usize;
    let dynstr_end = dynstr_start.checked_add(dynstr_section.sh_size as usize)?;
    let dynstr = data.get(dynstr_start..dynstr_end)?;
    let dynsym = parse_symbols(&data, dynsym_section.sh_offset, dynsym_section.sh_size).ok()?;
    let symbol_addr = dynsym
        .iter()
        .find(|sym| sym.is_defined() && get_string(dynstr, sym.st_name).ok() == Some(symbol))
        .map(|sym| base.saturating_add(sym.st_value) as usize)?;
    HOST_LIBC_SYMBOL_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(symbol, symbol_addr);
    Some(symbol_addr)
}

unsafe fn resolve_host_symbol_nocache(name: &'static [u8]) -> *mut c_void {
    let glibc_v34 = b"GLIBC_2.34\0";
    let glibc_v232 = b"GLIBC_2.3.2\0";
    let glibc_v225 = b"GLIBC_2.2.5\0";
    // Try versions in order: newest first, then NPTL baseline (2.3.2),
    // then legacy (2.2.5). For pthread_cond_*, the 2.3.2 version uses
    // the NPTL layout which is the current default; 2.2.5 is the old
    // LinuxThreads ABI with incompatible struct layout.
    let mut ptr = unsafe {
        crate::dlfcn_abi::dlvsym_next(
            name.as_ptr().cast::<libc::c_char>(),
            glibc_v34.as_ptr().cast::<libc::c_char>(),
        )
    };
    if ptr.is_null() {
        // SAFETY: NPTL baseline — preferred for pthread_cond_* and pthread_mutex_*.
        ptr = unsafe {
            crate::dlfcn_abi::dlvsym_next(
                name.as_ptr().cast::<libc::c_char>(),
                glibc_v232.as_ptr().cast::<libc::c_char>(),
            )
        };
    }
    if ptr.is_null() {
        // SAFETY: oldest baseline — LinuxThreads era.
        ptr = unsafe {
            crate::dlfcn_abi::dlvsym_next(
                name.as_ptr().cast::<libc::c_char>(),
                glibc_v225.as_ptr().cast::<libc::c_char>(),
            )
        };
    }
    if ptr.is_null() {
        // SAFETY: final RTLD_NEXT fallback.
        ptr = unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr().cast::<libc::c_char>()) };
    }
    ptr
}

fn host_libc_handle() -> Option<*mut c_void> {
    let cached = HOST_LIBC_HANDLE.load(Ordering::Acquire);
    if cached != 0 {
        return Some(cached as *mut c_void);
    }

    // SAFETY: loading the process' already-present glibc image by SONAME.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return None;
    }

    let handle_usize = handle as usize;
    match HOST_LIBC_HANDLE.compare_exchange(0, handle_usize, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Some(handle),
        Err(existing) => Some(existing as *mut c_void),
    }
}

unsafe fn resolve_host_symbol_via_libc_handle(name: &'static [u8]) -> *mut c_void {
    let Some(handle) = host_libc_handle() else {
        return std::ptr::null_mut();
    };
    // SAFETY: handle is a valid `dlopen` result and `name` is NUL-terminated.
    unsafe { libc::dlsym(handle, name.as_ptr().cast::<libc::c_char>()) }
}

unsafe fn resolve_host_symbol_with_aliases(names: &[&'static [u8]]) -> *mut c_void {
    for name in names {
        // SAFETY: each symbol name is a static NUL-terminated C string.
        let ptr = unsafe { resolve_host_symbol_via_libc_handle(name) };
        if !ptr.is_null() {
            return ptr;
        }
        // SAFETY: each symbol name is a static NUL-terminated C string.
        let ptr = unsafe { resolve_host_symbol_nocache(name) };
        if !ptr.is_null() {
            return ptr;
        }
    }
    std::ptr::null_mut()
}

fn load_cached_host_ptr(cache: &std::sync::atomic::AtomicUsize) -> Option<usize> {
    let ptr = cache.load(Ordering::Acquire);
    (ptr != 0).then_some(ptr)
}

fn cache_host_ptr(cache: &std::sync::atomic::AtomicUsize, ptr: usize) -> Option<usize> {
    if ptr == 0 {
        return None;
    }
    let _ = cache.compare_exchange(0, ptr, Ordering::AcqRel, Ordering::Acquire);
    Some(cache.load(Ordering::Acquire))
}

unsafe fn resolve_cached_host_thread_symbol(
    cache: &std::sync::atomic::AtomicUsize,
    public_name: &'static str,
    public_symbol: &'static [u8],
) -> Option<usize> {
    if let Some(ptr) = load_cached_host_ptr(cache) {
        return Some(ptr);
    }
    if let Some(ptr) = resolve_loaded_libc_symbol_direct(public_name) {
        return cache_host_ptr(cache, ptr);
    }
    // SAFETY: symbol name is NUL-terminated and belongs to the host pthread surface.
    let ptr = unsafe { resolve_host_symbol_nocache(public_symbol) } as usize;
    cache_host_ptr(cache, ptr)
}

unsafe fn resolve_cached_pthread_attr_symbol(
    slot: &OnceLock<usize>,
    names: &[&'static [u8]],
) -> Option<usize> {
    let ptr = *slot.get_or_init(|| unsafe { resolve_host_symbol_with_aliases(names) as usize });
    (ptr != 0).then_some(ptr)
}

unsafe fn resolved_pthread_attr_init_fn() -> Option<ResolvedPthreadAttrInitFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_INIT_PTR,
            &[b"pthread_attr_init\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrInitFn>(ptr) })
}

unsafe fn resolved_pthread_attr_destroy_fn() -> Option<ResolvedPthreadAttrDestroyFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_DESTROY_PTR,
            &[b"pthread_attr_destroy\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrDestroyFn>(ptr) })
}

unsafe fn resolved_pthread_attr_setdetachstate_fn() -> Option<ResolvedPthreadAttrSetdetachstateFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_SETDETACHSTATE_PTR,
            &[b"pthread_attr_setdetachstate\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrSetdetachstateFn>(ptr) })
}

unsafe fn resolved_pthread_attr_getdetachstate_fn() -> Option<ResolvedPthreadAttrGetdetachstateFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_GETDETACHSTATE_PTR,
            &[b"pthread_attr_getdetachstate\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrGetdetachstateFn>(ptr) })
}

unsafe fn resolved_pthread_attr_setguardsize_fn() -> Option<ResolvedPthreadAttrSetguardsizeFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_SETGUARDSIZE_PTR,
            &[b"pthread_attr_setguardsize\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrSetguardsizeFn>(ptr) })
}

unsafe fn resolved_pthread_attr_getguardsize_fn() -> Option<ResolvedPthreadAttrGetguardsizeFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_GETGUARDSIZE_PTR,
            &[b"pthread_attr_getguardsize\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrGetguardsizeFn>(ptr) })
}

unsafe fn resolved_pthread_attr_setstack_fn() -> Option<ResolvedPthreadAttrSetstackFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_SETSTACK_PTR,
            &[b"pthread_attr_setstack\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrSetstackFn>(ptr) })
}

unsafe fn resolved_pthread_attr_getstack_fn() -> Option<ResolvedPthreadAttrGetstackFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_GETSTACK_PTR,
            &[b"pthread_attr_getstack\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrGetstackFn>(ptr) })
}

unsafe fn resolved_pthread_attr_setstacksize_fn() -> Option<ResolvedPthreadAttrSetstacksizeFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_SETSTACKSIZE_PTR,
            &[b"pthread_attr_setstacksize\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrSetstacksizeFn>(ptr) })
}

unsafe fn resolved_pthread_attr_getstacksize_fn() -> Option<ResolvedPthreadAttrGetstacksizeFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_GETSTACKSIZE_PTR,
            &[b"pthread_attr_getstacksize\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrGetstacksizeFn>(ptr) })
}

unsafe fn resolved_pthread_attr_setinheritsched_fn() -> Option<ResolvedPthreadAttrSetinheritschedFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_SETINHERITSCHED_PTR,
            &[b"pthread_attr_setinheritsched\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrSetinheritschedFn>(ptr) })
}

unsafe fn resolved_pthread_attr_getinheritsched_fn() -> Option<ResolvedPthreadAttrGetinheritschedFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_GETINHERITSCHED_PTR,
            &[b"pthread_attr_getinheritsched\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrGetinheritschedFn>(ptr) })
}

unsafe fn resolved_pthread_attr_setschedpolicy_fn() -> Option<ResolvedPthreadAttrSetschedpolicyFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_SETSCHEDPOLICY_PTR,
            &[b"pthread_attr_setschedpolicy\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrSetschedpolicyFn>(ptr) })
}

unsafe fn resolved_pthread_attr_getschedpolicy_fn() -> Option<ResolvedPthreadAttrGetschedpolicyFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_GETSCHEDPOLICY_PTR,
            &[b"pthread_attr_getschedpolicy\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrGetschedpolicyFn>(ptr) })
}

unsafe fn resolved_pthread_attr_setschedparam_fn() -> Option<ResolvedPthreadAttrSetschedparamFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_SETSCHEDPARAM_PTR,
            &[b"pthread_attr_setschedparam\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrSetschedparamFn>(ptr) })
}

unsafe fn resolved_pthread_attr_getschedparam_fn() -> Option<ResolvedPthreadAttrGetschedparamFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_GETSCHEDPARAM_PTR,
            &[b"pthread_attr_getschedparam\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrGetschedparamFn>(ptr) })
}

unsafe fn resolved_pthread_attr_setaffinity_np_fn() -> Option<ResolvedPthreadAttrSetaffinityNpFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_SETAFFINITY_NP_PTR,
            &[b"pthread_attr_setaffinity_np\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrSetaffinityNpFn>(ptr) })
}

unsafe fn resolved_pthread_attr_setsigmask_np_fn() -> Option<ResolvedPthreadAttrSetsigmaskNpFn> {
    let ptr = unsafe {
        resolve_cached_pthread_attr_symbol(
            &RESOLVED_PTHREAD_ATTR_SETSIGMASK_NP_PTR,
            &[b"pthread_attr_setsigmask_np\0"],
        )
    }?;
    Some(unsafe { std::mem::transmute::<usize, ResolvedPthreadAttrSetsigmaskNpFn>(ptr) })
}

unsafe fn host_pthread_create_fn() -> Option<HostPthreadCreateFn> {
    let ptr = unsafe {
        resolve_cached_host_thread_symbol(
            &HOST_PTHREAD_CREATE_PTR,
            "pthread_create",
            b"pthread_create\0",
        )
    }?;
    // SAFETY: resolved symbol has pthread_create ABI.
    Some(unsafe { std::mem::transmute::<usize, HostPthreadCreateFn>(ptr) })
}

unsafe fn host_pthread_join_fn() -> Option<HostPthreadJoinFn> {
    let ptr = unsafe {
        resolve_cached_host_thread_symbol(&HOST_PTHREAD_JOIN_PTR, "pthread_join", b"pthread_join\0")
    }?;
    // SAFETY: resolved symbol has pthread_join ABI.
    Some(unsafe { std::mem::transmute::<usize, HostPthreadJoinFn>(ptr) })
}

unsafe fn host_pthread_detach_fn() -> Option<HostPthreadDetachFn> {
    let ptr = unsafe {
        resolve_cached_host_thread_symbol(
            &HOST_PTHREAD_DETACH_PTR,
            "pthread_detach",
            b"pthread_detach\0",
        )
    }?;
    // SAFETY: resolved symbol has pthread_detach ABI.
    Some(unsafe { std::mem::transmute::<usize, HostPthreadDetachFn>(ptr) })
}

unsafe fn host_pthread_self_fn() -> Option<HostPthreadSelfFn> {
    let ptr = unsafe {
        resolve_cached_host_thread_symbol(&HOST_PTHREAD_SELF_PTR, "pthread_self", b"pthread_self\0")
    }?;
    // SAFETY: resolved symbol has pthread_self ABI.
    Some(unsafe { std::mem::transmute::<usize, HostPthreadSelfFn>(ptr) })
}

unsafe fn host_pthread_equal_fn() -> Option<HostPthreadEqualFn> {
    let ptr = unsafe {
        resolve_cached_host_thread_symbol(
            &HOST_PTHREAD_EQUAL_PTR,
            "pthread_equal",
            b"pthread_equal\0",
        )
    }?;
    // SAFETY: resolved symbol has pthread_equal ABI.
    Some(unsafe { std::mem::transmute::<usize, HostPthreadEqualFn>(ptr) })
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

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
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

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
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

unsafe fn host_pthread_mutex_timedlock_fn() -> Option<HostPthreadMutexTimedlockFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_mutex_timedlock\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutex_timedlock ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexTimedlockFn>(ptr) })
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

unsafe fn resolved_pthread_mutexattr_init_fn() -> Option<HostPthreadMutexattrInitFn> {
    let ptr = unsafe {
        resolve_host_symbol_with_aliases(&[
            b"pthread_mutexattr_init\0",
            b"__pthread_mutexattr_init\0",
        ])
    };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutexattr_init ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrInitFn>(ptr) })
    }
}

unsafe fn resolved_pthread_mutexattr_destroy_fn() -> Option<HostPthreadMutexattrDestroyFn> {
    let ptr = unsafe {
        resolve_host_symbol_with_aliases(&[
            b"pthread_mutexattr_destroy\0",
            b"__pthread_mutexattr_destroy\0",
        ])
    };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutexattr_destroy ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrDestroyFn>(ptr) })
    }
}

unsafe fn resolved_pthread_mutexattr_settype_fn() -> Option<HostPthreadMutexattrSettypeFn> {
    let ptr = unsafe {
        resolve_host_symbol_with_aliases(&[
            b"pthread_mutexattr_settype\0",
            b"__pthread_mutexattr_settype\0",
        ])
    };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutexattr_settype ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrSettypeFn>(ptr) })
    }
}

unsafe fn resolved_pthread_mutexattr_gettype_fn() -> Option<HostPthreadMutexattrGettypeFn> {
    let ptr = unsafe {
        resolve_host_symbol_with_aliases(&[
            b"pthread_mutexattr_gettype\0",
            b"__pthread_mutexattr_gettype\0",
        ])
    };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutexattr_gettype ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrGettypeFn>(ptr) })
    }
}

unsafe fn resolved_pthread_mutexattr_setprotocol_fn() -> Option<HostPthreadMutexattrSetprotocolFn> {
    let ptr = unsafe {
        resolve_host_symbol_with_aliases(&[
            b"pthread_mutexattr_setprotocol\0",
            b"__pthread_mutexattr_setprotocol\0",
        ])
    };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutexattr_setprotocol ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrSetprotocolFn>(ptr) })
    }
}

unsafe fn resolved_pthread_mutexattr_getprotocol_fn() -> Option<HostPthreadMutexattrGetprotocolFn> {
    let ptr = unsafe {
        resolve_host_symbol_with_aliases(&[
            b"pthread_mutexattr_getprotocol\0",
            b"__pthread_mutexattr_getprotocol\0",
        ])
    };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutexattr_getprotocol ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrGetprotocolFn>(ptr) })
    }
}

unsafe fn resolved_pthread_mutexattr_setpshared_fn() -> Option<HostPthreadMutexattrSetpsharedFn> {
    let ptr = unsafe {
        resolve_host_symbol_with_aliases(&[
            b"pthread_mutexattr_setpshared\0",
            b"__pthread_mutexattr_setpshared\0",
        ])
    };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutexattr_setpshared ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrSetpsharedFn>(ptr) })
    }
}

unsafe fn resolved_pthread_mutexattr_getpshared_fn() -> Option<HostPthreadMutexattrGetpsharedFn> {
    let ptr = unsafe {
        resolve_host_symbol_with_aliases(&[
            b"pthread_mutexattr_getpshared\0",
            b"__pthread_mutexattr_getpshared\0",
        ])
    };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutexattr_getpshared ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrGetpsharedFn>(ptr) })
    }
}

unsafe fn resolved_pthread_mutexattr_setrobust_fn() -> Option<HostPthreadMutexattrSetrobustFn> {
    let ptr = unsafe {
        resolve_host_symbol_with_aliases(&[
            b"pthread_mutexattr_setrobust\0",
            b"__pthread_mutexattr_setrobust\0",
        ])
    };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutexattr_setrobust ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrSetrobustFn>(ptr) })
    }
}

unsafe fn resolved_pthread_mutexattr_getrobust_fn() -> Option<HostPthreadMutexattrGetrobustFn> {
    let ptr = unsafe {
        resolve_host_symbol_with_aliases(&[
            b"pthread_mutexattr_getrobust\0",
            b"__pthread_mutexattr_getrobust\0",
        ])
    };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutexattr_getrobust ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrGetrobustFn>(ptr) })
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

unsafe fn host_pthread_condattr_getclock_fn() -> Option<HostPthreadCondattrGetclockFn> {
    let ptr = unsafe {
        resolve_cached_host_thread_symbol(
            &HOST_PTHREAD_CONDATTR_GETCLOCK_PTR,
            "pthread_condattr_getclock",
            b"pthread_condattr_getclock\0",
        )
    }?;
    // SAFETY: resolved symbol has pthread_condattr_getclock ABI.
    Some(unsafe { std::mem::transmute::<usize, HostPthreadCondattrGetclockFn>(ptr) })
}

pub(crate) fn prewarm_host_thread_lifecycle_symbols() {
    // Resolve the thread lifecycle surface while startup is still in bootstrap
    // passthrough, before constructors or early runtime paths can create or
    // detach threads.
    crate::host_resolve::bootstrap_host_symbols();
    unsafe {
        let _ = host_pthread_self_fn();
        let _ = host_pthread_equal_fn();
        let _ = host_pthread_create_fn();
        let _ = host_pthread_join_fn();
        let _ = host_pthread_detach_fn();
    }
}

pub(crate) fn prewarm_host_thread_symbols() {
    prewarm_host_thread_lifecycle_symbols();
    // Resolve the rest of the host pthread surface while startup is still in
    // bootstrap passthrough, so active-mode execution does not lazily enter
    // dl* symbol resolution through validated string/memory paths.
    unsafe {
        let _ = host_pthread_key_create_fn();
        let _ = host_pthread_key_delete_fn();
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let _ = host_pthread_getspecific_fn();
            let _ = host_pthread_setspecific_fn();
        }
        let _ = host_pthread_mutex_init_fn();
        let _ = host_pthread_mutex_destroy_fn();
        let _ = host_pthread_mutex_lock_fn();
        let _ = host_pthread_mutex_trylock_fn();
        let _ = host_pthread_mutex_unlock_fn();
        let _ = resolved_pthread_mutexattr_init_fn();
        let _ = resolved_pthread_mutexattr_destroy_fn();
        let _ = resolved_pthread_mutexattr_settype_fn();
        let _ = resolved_pthread_mutexattr_gettype_fn();
        let _ = resolved_pthread_mutexattr_setprotocol_fn();
        let _ = resolved_pthread_mutexattr_getprotocol_fn();
        let _ = resolved_pthread_mutexattr_setpshared_fn();
        let _ = resolved_pthread_mutexattr_getpshared_fn();
        let _ = resolved_pthread_mutexattr_setrobust_fn();
        let _ = resolved_pthread_mutexattr_getrobust_fn();
        let _ = host_pthread_cond_init_fn();
        let _ = host_pthread_cond_destroy_fn();
        let _ = host_pthread_cond_wait_fn();
        let _ = host_pthread_cond_signal_fn();
        let _ = host_pthread_cond_broadcast_fn();
        let _ = host_pthread_cond_timedwait_fn();
    }
}

// Host pthread mutexattr resolution is used in host mode to preserve
// LD_PRELOAD compatibility; native encoding remains when FORCE_NATIVE_MUTEX
// is enabled.

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
    // SAFETY: `base` comes from non-null `mutex`; adding a small in-object offset.
    let ptr = unsafe { base.add(MUTEX_MAGIC_OFFSET) };
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

fn is_managed_mutex(mutex: *mut libc::pthread_mutex_t) -> bool {
    let Some(magic_ptr) = mutex_magic_ptr(mutex) else {
        return false;
    };
    // SAFETY: alignment and non-null checked in `mutex_magic_ptr`.
    let magic = unsafe { &*magic_ptr };
    magic.load(Ordering::Acquire) == MANAGED_MUTEX_MAGIC
}

/// Returns a pointer to the mutex type field within the managed metadata
/// overlay. Layout: [lock_word][magic][type]...
fn mutex_type_ptr(mutex: *mut libc::pthread_mutex_t) -> Option<*mut AtomicI32> {
    if mutex.is_null() {
        return None;
    }
    let base = mutex.cast::<u8>();
    // SAFETY: `base` comes from non-null `mutex`; adding a small in-object offset.
    let ptr = unsafe { base.add(MUTEX_TYPE_OFFSET) };
    let align = std::mem::align_of::<AtomicI32>();
    if !(ptr as usize).is_multiple_of(align) {
        return None;
    }
    Some(ptr.cast::<AtomicI32>())
}

/// Returns a pointer to the owner tid field within the managed metadata
/// overlay. Layout: [lock_word][magic][type][owner_tid]...
fn mutex_owner_ptr(mutex: *mut libc::pthread_mutex_t) -> Option<*mut AtomicI32> {
    if mutex.is_null() {
        return None;
    }
    let base = mutex.cast::<u8>();
    // SAFETY: `base` comes from non-null `mutex`; adding a small in-object offset.
    let ptr = unsafe { base.add(MUTEX_OWNER_OFFSET) };
    let align = std::mem::align_of::<AtomicI32>();
    if !(ptr as usize).is_multiple_of(align) {
        return None;
    }
    Some(ptr.cast::<AtomicI32>())
}

/// Returns a pointer to the lock count field within the managed metadata
/// overlay. Layout: [lock_word][magic][type][owner_tid][lock_count]...
fn mutex_lock_count_ptr(mutex: *mut libc::pthread_mutex_t) -> Option<*mut AtomicU32> {
    if mutex.is_null() {
        return None;
    }
    let base = mutex.cast::<u8>();
    // SAFETY: `base` comes from non-null `mutex`; adding a small in-object offset.
    let ptr = unsafe { base.add(MUTEX_LOCK_COUNT_OFFSET) };
    let align = std::mem::align_of::<AtomicU32>();
    if !(ptr as usize).is_multiple_of(align) {
        return None;
    }
    Some(ptr.cast::<AtomicU32>())
}

/// Read the mutex type stored in the managed metadata overlay. Returns NORMAL (0) for unmanaged
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
    // SAFETY: `base` comes from non-null `rwlock`; adding a small in-object offset.
    let ptr = unsafe { base.add(RWLOCK_MAGIC_OFFSET) };
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

fn is_managed_condvar(cond: *mut libc::pthread_cond_t) -> bool {
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return false;
    };
    // SAFETY: alignment and non-null checked in `condvar_data_ptr`.
    let condvar = unsafe { &*cond_ptr };
    condvar.magic.load(Ordering::Acquire) == MANAGED_CONDVAR_MAGIC
}

#[inline]
fn native_pthread_self() -> libc::pthread_t {
    if current_threading_backend() == THREAD_BACKEND_HOST
        && let Some(cached_self) = CURRENT_PTHREAD_SELF_CACHE
            .try_with(|cache| {
                let value = cache.get();
                (value != 0).then_some(value)
            })
            .ok()
            .flatten()
    {
        return cached_self;
    }

    if current_threading_backend() == THREAD_BACKEND_HOST
        && let Some(host_self) = crate::host_resolve::host_pthread_self_raw()
    {
        let host_thread = unsafe { host_self() };
        let _ = CURRENT_PTHREAD_SELF_CACHE.try_with(|cache| cache.set(host_thread));
        return host_thread;
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
    if a == b { 1 } else { 0 }
}

fn resolve_thread_tid(thread: libc::pthread_t) -> Option<i32> {
    let self_tid = core_self_tid();
    if self_tid > 0 && thread == native_pthread_self() {
        return Some(self_tid);
    }

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

    let detached_snapshot_tid = DETACHED_THREAD_TID_SNAPSHOTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&thread_key)
        .copied();
    if let Some(tid) = detached_snapshot_tid {
        if tid > 0 && thread_tid_appears_alive(tid) {
            return Some(tid);
        }
        DETACHED_THREAD_TID_SNAPSHOTS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&thread_key);
    }

    None
}

fn thread_tid_appears_alive(tid: i32) -> bool {
    if tid <= 0 {
        return false;
    }
    let pid = match syscall_result(unsafe { syscall0(libc::SYS_getpid as usize) }) {
        Ok(pid) => pid as i32,
        Err(_) => return false,
    };
    let rc = unsafe { syscall3(libc::SYS_tgkill as usize, pid as usize, tid as usize, 0) };
    match syscall_result(rc) {
        Ok(_) => true,
        Err(errno) => errno != libc::ESRCH,
    }
}

/// Parse `/proc/self/task/<tid>/maps` (or `/proc/self/maps` for the main thread)
/// to discover stack boundaries. Returns `(stack_start, stack_size)` where
/// `stack_start` is the lowest address of the stack mapping.
///
/// For the main thread the kernel labels the mapping `[stack]`. For spawned
/// threads there is no such label, but we can locate the mapping that contains
/// the current stack pointer.
fn stack_bounds_from_proc_maps(tid: i32) -> Option<(usize, usize)> {
    // Try thread-specific maps first, fall back to process-wide.
    let maps_content = std::fs::read_to_string(format!("/proc/self/task/{tid}/maps"))
        .or_else(|_| std::fs::read_to_string("/proc/self/maps"))
        .ok()?;

    // First pass: look for the explicit [stack] annotation (main thread).
    for line in maps_content.lines() {
        if line.ends_with("[stack]")
            && let Some((start, end)) = parse_maps_range(line)
        {
            return Some((start, end - start));
        }
    }

    // Second pass: find the mapping containing our current stack pointer.
    // This handles spawned threads whose stack mappings have no label.
    let sp: usize;
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: reading rsp is a single instruction with no side effects.
        unsafe { core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack)) };
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack)) };
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        return None;
    }

    for line in maps_content.lines() {
        if let Some((start, end)) = parse_maps_range(line)
            && sp >= start
            && sp < end
        {
            return Some((start, end - start));
        }
    }

    None
}

/// Extract (start_addr, end_addr) from a `/proc/self/maps` line.
/// Format: `start-end perms offset dev inode [pathname]`
fn parse_maps_range(line: &str) -> Option<(usize, usize)> {
    let range = line.split_whitespace().next()?;
    let mut parts = range.split('-');
    let start = usize::from_str_radix(parts.next()?, 16).ok()?;
    let end = usize::from_str_radix(parts.next()?, 16).ok()?;
    Some((start, end))
}

fn detached_thread_tid_snapshot(handle_ptr: *mut ThreadHandle) -> Option<i32> {
    if handle_ptr.is_null() {
        return None;
    }
    let tid = unsafe { (*handle_ptr).tid.load(Ordering::Acquire) };
    if tid > 0 {
        return Some(tid);
    }
    let self_tid = unsafe { (*handle_ptr).self_tid.load(Ordering::Acquire) };
    (self_tid > 0).then_some(self_tid)
}

fn clock_gettime_checked(clockid: c_int) -> Result<libc::timespec, c_int> {
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        syscall2(
            libc::SYS_clock_gettime as usize,
            clockid as usize,
            &mut now as *mut libc::timespec as usize,
        )
    };
    match syscall_result(rc) {
        Ok(_) => Ok(now),
        Err(errno) => Err(errno),
    }
}

/// Convert an absolute `timespec` deadline from `clockid` to `CLOCK_REALTIME`.
fn clock_convert_to_realtime(
    clockid: c_int,
    abstime: *const libc::timespec,
) -> Result<libc::timespec, c_int> {
    clock_convert_between(clockid, libc::CLOCK_REALTIME, abstime)
}

fn clock_convert_between(
    from_clockid: c_int,
    to_clockid: c_int,
    abstime: *const libc::timespec,
) -> Result<libc::timespec, c_int> {
    if from_clockid == to_clockid {
        // SAFETY: caller supplied a valid absolute timespec pointer.
        return Ok(unsafe { *abstime });
    }
    let clock_now = clock_gettime_checked(from_clockid)?;
    let target_now = clock_gettime_checked(to_clockid)?;
    let deadline = unsafe { &*abstime };
    let mut result = libc::timespec {
        tv_sec: target_now.tv_sec + (deadline.tv_sec - clock_now.tv_sec),
        tv_nsec: target_now.tv_nsec + (deadline.tv_nsec - clock_now.tv_nsec),
    };
    if result.tv_nsec >= 1_000_000_000 {
        result.tv_sec += 1;
        result.tv_nsec -= 1_000_000_000;
    } else if result.tv_nsec < 0 {
        result.tv_sec -= 1;
        result.tv_nsec += 1_000_000_000;
    }
    Ok(result)
}

fn condvar_clock_to_libc(clock: i32) -> c_int {
    if clock == PTHREAD_COND_CLOCK_MONOTONIC {
        libc::CLOCK_MONOTONIC
    } else {
        libc::CLOCK_REALTIME
    }
}

fn absolute_timespec_valid(abstime: *const libc::timespec) -> bool {
    if abstime.is_null() {
        return false;
    }
    let ts = unsafe { &*abstime };
    (0..1_000_000_000).contains(&ts.tv_nsec)
}

/// Futex wait with an absolute CLOCK_REALTIME deadline.
///
/// Linux `FUTEX_WAIT` expects a relative timeout, so convert the caller's
/// absolute pthread-style deadline to a per-call relative duration.
#[cfg(target_os = "linux")]
fn futex_wait_timed(
    word: &AtomicI32,
    expected: i32,
    abstime: *const libc::timespec,
    private: bool,
) -> c_int {
    let now = match clock_gettime_checked(libc::CLOCK_REALTIME) {
        Ok(now) => now,
        Err(errno) => {
            unsafe { set_abi_errno(errno) };
            return -1;
        }
    };
    let deadline = unsafe { &*abstime };
    let mut rel = libc::timespec {
        tv_sec: deadline.tv_sec - now.tv_sec,
        tv_nsec: deadline.tv_nsec - now.tv_nsec,
    };
    if rel.tv_nsec < 0 {
        rel.tv_sec -= 1;
        rel.tv_nsec += 1_000_000_000;
    }
    if rel.tv_sec < 0 || (rel.tv_sec == 0 && rel.tv_nsec <= 0) {
        unsafe { set_abi_errno(libc::ETIMEDOUT) };
        return -1;
    }
    let ret = unsafe {
        syscall4(
            libc::SYS_futex as usize,
            word as *const AtomicI32 as *const i32 as usize,
            (libc::FUTEX_WAIT as usize)
                | if private {
                    libc::FUTEX_PRIVATE_FLAG as usize
                } else {
                    0
                },
            expected as usize,
            &rel as *const libc::timespec as usize,
        )
    };
    match syscall_result(ret) {
        Ok(_) => 0,
        Err(errno) => {
            unsafe { set_abi_errno(errno) };
            -1
        }
    }
}

#[cfg(target_os = "linux")]
fn futex_wait_timed_private(
    word: &AtomicI32,
    expected: i32,
    abstime: *const libc::timespec,
) -> c_int {
    futex_wait_timed(word, expected, abstime, true)
}

#[cfg(target_os = "linux")]
fn futex_wait_timed_shared(
    word: &AtomicI32,
    expected: i32,
    abstime: *const libc::timespec,
) -> c_int {
    futex_wait_timed(word, expected, abstime, false)
}

#[allow(unsafe_code)]
unsafe fn native_pthread_create(
    thread_out: *mut libc::pthread_t,
    attr: *const libc::pthread_attr_t,
    start_routine: StartRoutine,
    arg: *mut c_void,
) -> c_int {
    if thread_out.is_null() {
        return libc::EINVAL;
    }

    // Extract attributes if provided; default to 0 (use core defaults).
    let mut stack_size: usize = 0;
    let mut detach_state: c_int = 0;
    if !attr.is_null() {
        if let Some(data_ptr) = managed_attr_data_for_host_translation(attr)
            && data_ptr.is_null()
        {
            return libc::EINVAL;
        }
        let mut handled = false;
        if let Some(data) = managed_attr_data_ptr_const(attr) {
            stack_size = unsafe { (*data).stack_size };
            detach_state = unsafe { (*data).detach_state };
            handled = true;
        }
        if !handled {
            let Some(getstacksize) = (unsafe { resolved_pthread_attr_getstacksize_fn() }) else {
                return libc::ENOSYS;
            };
            let rc = unsafe { getstacksize(attr, &mut stack_size) };
            if rc != 0 {
                return rc;
            }
            let Some(getdetachstate) = (unsafe { resolved_pthread_attr_getdetachstate_fn() }) else {
                return libc::ENOSYS;
            };
            let rc = unsafe { getdetachstate(attr, &mut detach_state) };
            if rc != 0 {
                return rc;
            }
        }
    }

    let handle_ptr =
        match unsafe { core_create_thread(start_routine as usize, arg as usize, stack_size) } {
            Ok(ptr) => ptr,
            Err(errno) => return errno,
        };

    let thread_key = handle_ptr as usize;

    let effective_stack_size = if stack_size > 0 {
        stack_size
    } else {
        attr_default_stack_size()
    };

    let mut registry = THREAD_HANDLE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if registry.contains_key(&thread_key) {
        let _ = unsafe { core_detach_thread(handle_ptr) };
        return libc::EAGAIN;
    }
    MANAGED_THREAD_TOMBSTONES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&thread_key);
    DETACHED_THREAD_TOMBSTONES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&thread_key);
    registry.insert(
        thread_key,
        ManagedThreadRecord {
            handle_raw: handle_ptr as usize,
            stack_size: effective_stack_size,
            detach_state,
        },
    );
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
        if let Some(tid) = detached_thread_tid_snapshot(handle_ptr) {
            DETACHED_THREAD_TID_SNAPSHOTS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(thread_key, tid);
        }
        MANAGED_THREAD_TOMBSTONES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(thread_key);
        DETACHED_THREAD_TOMBSTONES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(thread_key);
        let _ = unsafe { core_detach_thread(handle_ptr) };
    }

    0
}

fn managed_attr_data_for_host_translation(
    attr: *const libc::pthread_attr_t,
) -> Option<*const PthreadAttrData> {
    let data = attr_data_ptr_const(attr)?;
    // SAFETY: `data` came from `attr_data_ptr_const`, which validates alignment and non-null.
    let attr_ref = unsafe { &*data };
    if attr_ref.magic == MANAGED_ATTR_MAGIC {
        return Some(data);
    }
    // A fully zeroed overlay is our destroyed/uninitialized managed attr shape, not a
    // valid host pthread attr object. Reject rather than passing malformed bytes to glibc.
    if attr_ref.magic == 0
        && attr_ref.detach_state == 0
        && attr_ref.stack_size == 0
        && attr_ref.guard_size == 0
        && attr_ref.stack_addr == 0
        && attr_ref.inherit_sched == 0
        && attr_ref.sched_policy == 0
        && attr_ref.sched_priority == 0
        && attr_ref.flags == 0
    {
        return Some(std::ptr::null());
    }
    None
}

unsafe fn host_pthread_create_with_managed_attr(
    host_create: unsafe extern "C" fn(
        *mut libc::pthread_t,
        *const libc::pthread_attr_t,
        Option<StartRoutine>,
        *mut c_void,
    ) -> c_int,
    thread_out: *mut libc::pthread_t,
    attr: *const libc::pthread_attr_t,
    start_routine: Option<StartRoutine>,
    arg: *mut c_void,
) -> c_int {
    let Some(data_ptr) = managed_attr_data_for_host_translation(attr) else {
        return unsafe { host_create(thread_out, attr, start_routine, arg) };
    };
    if data_ptr.is_null() {
        return libc::EINVAL;
    }

    // SAFETY: `data_ptr` came from `managed_attr_data_for_host_translation`.
    let data = unsafe { &*data_ptr };
    let mut host_attr: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
    let Some(attr_init) = (unsafe { resolved_pthread_attr_init_fn() }) else {
        return libc::ENOSYS;
    };
    let init_rc = unsafe { attr_init(&mut host_attr) };
    if init_rc != 0 {
        return init_rc;
    }

    let Some(setdetachstate) = (unsafe { resolved_pthread_attr_setdetachstate_fn() }) else {
        return libc::ENOSYS;
    };
    let Some(setguardsize) = (unsafe { resolved_pthread_attr_setguardsize_fn() }) else {
        return libc::ENOSYS;
    };
    let Some(setstack) = (unsafe { resolved_pthread_attr_setstack_fn() }) else {
        return libc::ENOSYS;
    };
    let Some(setstacksize) = (unsafe { resolved_pthread_attr_setstacksize_fn() }) else {
        return libc::ENOSYS;
    };
    let Some(setinheritsched) = (unsafe { resolved_pthread_attr_setinheritsched_fn() }) else {
        return libc::ENOSYS;
    };
    let Some(setschedpolicy) = (unsafe { resolved_pthread_attr_setschedpolicy_fn() }) else {
        return libc::ENOSYS;
    };
    let Some(setschedparam) = (unsafe { resolved_pthread_attr_setschedparam_fn() }) else {
        return libc::ENOSYS;
    };
    let mut rc = unsafe { setdetachstate(&mut host_attr, data.detach_state) };
    if rc == 0 {
        rc = unsafe { setguardsize(&mut host_attr, data.guard_size) };
    }
    if rc == 0 {
        if data.stack_addr != 0 {
            rc = unsafe { setstack(&mut host_attr, data.stack_addr as *mut c_void, data.stack_size) };
        } else {
            rc = unsafe { setstacksize(&mut host_attr, data.stack_size) };
        }
    }
    if rc == 0 {
        rc = unsafe { setinheritsched(&mut host_attr, data.inherit_sched) };
    }
    if rc == 0 {
        rc = unsafe { setschedpolicy(&mut host_attr, data.sched_policy) };
    }
    if rc == 0 {
        let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
        param.sched_priority = data.sched_priority;
        rc = unsafe { setschedparam(&mut host_attr, &param) };
    }
    if rc == 0 && data.flags & 0b01 != 0 {
        let Some(setaffinity_np) = (unsafe { resolved_pthread_attr_setaffinity_np_fn() }) else {
            return libc::ENOSYS;
        };
        let key = attr as usize;
        let reg = EXTENDED_ATTR_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(ext) = reg.get(&key)
            && let Some((cpusetsize, mask_bytes)) = &ext.affinity
        {
            rc = unsafe {
                setaffinity_np(
                    &mut host_attr,
                    *cpusetsize,
                    mask_bytes.as_ptr().cast::<libc::cpu_set_t>(),
                )
            };
        }
    }
    if rc == 0 && data.flags & 0b10 != 0 {
        let Some(setsigmask_np) = (unsafe { resolved_pthread_attr_setsigmask_np_fn() }) else {
            return libc::ENOSYS;
        };
        let key = attr as usize;
        let reg = EXTENDED_ATTR_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(ext) = reg.get(&key)
            && let Some(mask_bytes) = &ext.sigmask
        {
            rc = unsafe { setsigmask_np(&mut host_attr, mask_bytes.as_ptr().cast::<libc::sigset_t>()) };
        }
    }

    let result = if rc == 0 {
        unsafe { host_create(thread_out, &host_attr, start_routine, arg) }
    } else {
        rc
    };
    if let Some(attr_destroy) = unsafe { resolved_pthread_attr_destroy_fn() } {
        let _ = unsafe { attr_destroy(&mut host_attr) };
    }
    result
}

#[allow(unsafe_code)]
unsafe fn native_pthread_join(thread: libc::pthread_t, retval: *mut *mut c_void) -> c_int {
    let thread_key = thread as usize;
    let handle_ptr = thread as *mut ThreadHandle;

    // Self-join detection: compare handles directly for O(1) reliability.
    if let Some(my_handle) = core_handle_for_tid(core_self_tid())
        && handle_ptr == my_handle
    {
        return libc::EDEADLK;
    }

    // After a successful pthread_detach, the handle has been consumed: it has
    // been removed from THREAD_HANDLE_REGISTRY and a tombstone recorded. A
    // subsequent pthread_join on that handle therefore refers to no joinable
    // thread, and the correct error is ESRCH (not EINVAL). POSIX says joining
    // a detached thread is undefined; we choose the same convention used for
    // joining an already-joined handle so callers see consistent behavior.
    if is_detached_thread_handle(thread) {
        return libc::ESRCH;
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
            DETACHED_THREAD_TID_SNAPSHOTS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&thread_key);
            MANAGED_THREAD_TOMBSTONES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(thread_key);
            DETACHED_THREAD_TOMBSTONES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&thread_key);
            0
        }
        Err(errno) => errno,
    }
}

#[allow(unsafe_code)]
unsafe fn native_pthread_detach(thread: libc::pthread_t) -> c_int {
    let thread_key = thread as usize;
    let handle_ptr = thread as *mut ThreadHandle;

    // After a successful pthread_detach, the handle is consumed (removed from
    // THREAD_HANDLE_REGISTRY with a tombstone). A second detach on that handle
    // therefore refers to no live thread; ESRCH is the consistent answer
    // (matching the analogous post-join cases). POSIX leaves double-detach
    // undefined, so this is a permissible choice and matches the project's
    // existing test contract for consumed handles.
    if is_detached_thread_handle(thread) {
        return libc::ESRCH;
    }

    // Verify this is a valid managed thread handle that we know about
    // BEFORE dereferencing it. Callers may pass arbitrary `pthread_t`
    // values (including garbage from buggy code or test fuzzers); we must
    // not dereference until the registry confirms the handle is live.
    let is_managed = {
        let registry = THREAD_HANDLE_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        registry.contains_key(&thread_key)
    };

    if !is_managed {
        return libc::ESRCH;
    }

    // Now safe to dereference: registry membership proves the handle is a
    // live, properly aligned ThreadHandle owned by the runtime.
    let detached_tid_snapshot = detached_thread_tid_snapshot(handle_ptr);

    match unsafe { core_detach_thread(handle_ptr) } {
        Ok(()) => {
            if let Some(tid) = detached_tid_snapshot {
                DETACHED_THREAD_TID_SNAPSHOTS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(thread_key, tid);
            }
            // Remove from registry after successful detach.
            let mut registry = THREAD_HANDLE_REGISTRY
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            registry.remove(&thread_key);
            MANAGED_THREAD_TOMBSTONES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(thread_key);
            DETACHED_THREAD_TOMBSTONES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(thread_key);
            0
        }
        Err(errno) => errno,
    }
}

#[cfg(target_os = "linux")]
fn futex_wait_private(word: &AtomicI32, expected: i32) -> c_int {
    // SAFETY: Linux futex syscall with valid userspace address and null timeout.
    let ret = unsafe {
        syscall4(
            libc::SYS_futex as usize,
            word as *const AtomicI32 as *const i32 as usize,
            (libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG) as usize,
            expected as usize,
            std::ptr::null::<libc::timespec>() as usize,
        )
    };
    match syscall_result(ret) {
        Ok(v) => v as c_int,
        Err(errno) => {
            unsafe { set_abi_errno(errno) };
            -1
        }
    }
}

#[cfg(target_os = "linux")]
fn futex_wake_private(word: &AtomicI32, count: i32) -> c_int {
    // SAFETY: Linux futex syscall with valid userspace address.
    let ret = unsafe {
        syscall3(
            libc::SYS_futex as usize,
            word as *const AtomicI32 as *const i32 as usize,
            (libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG) as usize,
            count as usize,
        )
    };
    match syscall_result(ret) {
        Ok(v) => v as c_int,
        Err(errno) => {
            unsafe { set_abi_errno(errno) };
            -1
        }
    }
}

fn futex_lock_normal(word: &AtomicI32) -> c_int {
    if matches!(
        PTHREAD_MUTEX_HTM_SITE.run(|| {
            if word.load(Ordering::Acquire) == 0 {
                word.store(1, Ordering::Release);
                true
            } else {
                false
            }
        }),
        Ok(true)
    ) {
        return 0;
    }

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
            let errno = unsafe { std::ptr::read_volatile(crate::errno_abi::__errno_location()) };
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
            let errno = unsafe { std::ptr::read_volatile(crate::errno_abi::__errno_location()) };
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
            let errno = unsafe { std::ptr::read_volatile(crate::errno_abi::__errno_location()) };
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
        let errno = unsafe { std::ptr::read_volatile(crate::errno_abi::__errno_location()) };
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
        let errno = unsafe { std::ptr::read_volatile(crate::errno_abi::__errno_location()) };
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
    PTHREAD_MUTEX_HTM_SITE.reset_for_tests();
}

/// Test hook: force mutex/condvar lifecycle operations onto the native path.
#[doc(hidden)]
pub fn pthread_mutex_force_native_for_tests() {
    FORCE_NATIVE_MUTEX.store(true, Ordering::Release);
}

/// Test hook: force native mutex/condvar behavior and return the previous mode
/// so callers can restore it afterwards.
#[doc(hidden)]
pub fn pthread_mutex_swap_force_native_for_tests() -> bool {
    FORCE_NATIVE_MUTEX.swap(true, Ordering::AcqRel)
}

/// Test hook: restore the mutex/condvar delegation mode after temporarily
/// forcing native behavior in a test.
#[doc(hidden)]
pub fn pthread_mutex_restore_for_tests(previous: bool) {
    FORCE_NATIVE_MUTEX.store(previous, Ordering::Release);
}

/// Test hook: snapshot spin/wait/wake branch counters.
#[doc(hidden)]
#[must_use]
pub fn pthread_mutex_branch_counters_for_tests() -> (u64, u64, u64) {
    mutex_branch_counters()
}

/// Test hook: snapshot HTM controller state for the native mutex fast path.
#[doc(hidden)]
#[must_use]
pub fn pthread_mutex_htm_snapshot_for_tests() -> HtmSiteSnapshot {
    PTHREAD_MUTEX_HTM_SITE.snapshot()
}

/// Test hook: force thread lifecycle operations (create/join/detach/self/equal)
/// to use the native implementation, bypassing host glibc delegation.
#[doc(hidden)]
pub fn pthread_threading_force_native_for_tests() {
    FORCE_NATIVE_THREADING_OVERRIDE.with(|override_cell| override_cell.set(Some(true)));
}

/// Test hook: force native threading and return the previous mode so callers
/// can restore it afterwards.
#[doc(hidden)]
pub fn pthread_threading_swap_force_native_for_tests() -> bool {
    FORCE_NATIVE_THREADING_OVERRIDE.with(|override_cell| {
        let previous = override_cell
            .get()
            .unwrap_or_else(|| FORCE_NATIVE_THREADING.load(Ordering::Acquire));
        override_cell.set(Some(true));
        previous
    })
}

/// Test hook: restore the thread lifecycle delegation mode after temporarily
/// forcing native behavior in a test.
#[doc(hidden)]
pub fn pthread_threading_restore_for_tests(previous: bool) {
    FORCE_NATIVE_THREADING_OVERRIDE.with(|override_cell| override_cell.set(Some(previous)));
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
    attr: *const libc::pthread_attr_t,
    start_routine: Option<StartRoutine>,
    arg: *mut c_void,
) -> c_int {
    if thread_out.is_null() || start_routine.is_none() {
        return libc::EINVAL;
    }
    // Clear __libc_single_threaded on first thread creation.
    crate::glibc_internal_abi::__libc_single_threaded
        .store(0, std::sync::atomic::Ordering::Release);
    let force_native = force_native_threading_enabled();
    // Prefer host pthread_create for correct TLS setup, stack guard pages,
    // and compatibility with programs that depend on glibc thread internals
    // (Python, Node.js, etc.).
    if !force_native && let Some(host_create) = crate::host_resolve::host_pthread_create_raw() {
        return unsafe {
            host_pthread_create_with_managed_attr(host_create, thread_out, attr, start_routine, arg)
        };
    }
    let start = start_routine.unwrap_or_else(|| unreachable!("start routine checked above"));
    // SAFETY: pointers and start routine are validated by this wrapper.
    unsafe { native_pthread_create(thread_out, attr, start, arg) }
}

/// POSIX `pthread_join`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_join(thread: libc::pthread_t, retval: *mut *mut c_void) -> c_int {
    if !force_native_threading_enabled()
        && !is_managed_thread_handle(thread)
        && let Some(host_join) = crate::host_resolve::host_pthread_join_raw()
    {
        return unsafe { host_join(thread, retval) };
    }
    unsafe { native_pthread_join(thread, retval) }
}

/// POSIX `pthread_detach`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_detach(thread: libc::pthread_t) -> c_int {
    if !force_native_threading_enabled()
        && !is_managed_thread_handle(thread)
        && let Some(host_detach) = crate::host_resolve::host_pthread_detach_raw()
    {
        return unsafe { host_detach(thread) };
    }
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
    if mutex.is_null() {
        return libc::EINVAL;
    }

    // Always prefer host delegation — see CRITICAL comment in pthread_cond_init.
    // Mutex and condvar init must use the same implementation (host or native).
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire)
        && let Some(host_init) = unsafe { host_pthread_mutex_init_fn() }
    {
        return unsafe { host_init(mutex, attr) };
    }

    // Read the mutex type from the attr if provided.
    let mutex_type = if attr.is_null() {
        PTHREAD_MUTEX_NORMAL_TYPE
    } else {
        let word = unsafe { *(attr.cast::<c_int>()) };
        if !mutexattr_word_valid(word) {
            return libc::EINVAL;
        }
        if decode_mutexattr_protocol(word) != libc::PTHREAD_PRIO_NONE
            || decode_mutexattr_pshared(word) != libc::PTHREAD_PROCESS_PRIVATE
            || decode_mutexattr_robust(word) != libc::PTHREAD_MUTEX_STALLED
        {
            return libc::EINVAL;
        }
        decode_mutexattr_type(word)
    };

    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    let Some(type_ptr) = mutex_type_ptr(mutex) else {
        return libc::EINVAL;
    };
    let Some(owner_ptr) = mutex_owner_ptr(mutex) else {
        return libc::EINVAL;
    };
    let Some(count_ptr) = mutex_lock_count_ptr(mutex) else {
        return libc::EINVAL;
    };

    if !mark_managed_mutex(mutex) {
        return libc::EINVAL;
    }

    // SAFETY: pointers are alignment-checked and point to caller-owned mutex storage.
    let word = unsafe { &*word_ptr };
    let mtype = unsafe { &*type_ptr };
    let owner = unsafe { &*owner_ptr };
    let count = unsafe { &*count_ptr };

    word.store(0, Ordering::Release);
    mtype.store(mutex_type, Ordering::Release);
    owner.store(MUTEX_NO_OWNER, Ordering::Release);
    count.store(0, Ordering::Release);
    0
}

/// POSIX `pthread_mutex_destroy`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }

    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };

    if !is_managed_mutex(mutex) && !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_destroy) = unsafe { host_pthread_mutex_destroy_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_destroy(mutex) };
        }
    }
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
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    let force_native = FORCE_NATIVE_MUTEX.load(Ordering::Acquire);
    if !is_managed_mutex(mutex) {
        if !force_native {
            // SAFETY: host symbol lookup/transmute guarantees ABI if present.
            if let Some(host_lock) = unsafe { host_pthread_mutex_lock_fn() } {
                // SAFETY: direct call through resolved host symbol.
                return unsafe { host_lock(mutex) };
            }
        }
        return libc::EINVAL;
    }
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
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    let force_native = FORCE_NATIVE_MUTEX.load(Ordering::Acquire);
    if !is_managed_mutex(mutex) {
        if !force_native {
            // SAFETY: host symbol lookup/transmute guarantees ABI if present.
            if let Some(host_trylock) = unsafe { host_pthread_mutex_trylock_fn() } {
                // SAFETY: direct call through resolved host symbol.
                return unsafe { host_trylock(mutex) };
            }
        }
        return libc::EINVAL;
    }
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
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    let force_native = FORCE_NATIVE_MUTEX.load(Ordering::Acquire);
    if !is_managed_mutex(mutex) {
        if !force_native {
            // SAFETY: host symbol lookup/transmute guarantees ABI if present.
            if let Some(host_unlock) = unsafe { host_pthread_mutex_unlock_fn() } {
                // SAFETY: direct call through resolved host symbol.
                return unsafe { host_unlock(mutex) };
            }
        }
        return libc::EINVAL;
    }
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
    if cond.is_null() {
        return libc::EINVAL;
    }

    // ╔══════════════════════════════════════════════════════════════════╗
    // ║ CRITICAL: Always delegate to host regardless of attr.          ║
    // ║                                                                ║
    // ║ DO NOT add an `attr.is_null()` guard here. Python 3.13 passes ║
    // ║ non-null attrs with CLOCK_MONOTONIC. If we use our native      ║
    // ║ condvar init with a host-initialized mutex, pthread_cond_wait  ║
    // ║ will fail because the native condvar manipulates the mutex     ║
    // ║ futex word directly, which is incompatible with glibc's        ║
    // ║ internal mutex layout. Both mutex and condvar MUST be          ║
    // ║ initialized by the same implementation (host or native).       ║
    // ╚══════════════════════════════════════════════════════════════════╝
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire)
        && let Some(host_init) = unsafe { host_pthread_cond_init_fn() }
    {
        // If attr uses our custom encoding (valid bit set), translate to
        // host-compatible format before delegating. Same issue as mutex:
        // our bitfield layout differs from glibc's internal layout.
        if !attr.is_null() {
            let word = unsafe { *(attr.cast::<c_int>()) };
            if word == CONDATTR_DESTROYED_SENTINEL {
                return libc::EINVAL;
            }
            if word & CONDATTR_VALID_BIT != 0 && condattr_word_valid(word) {
                let clock = decode_condattr_clock(word);
                let mut host_attr: libc::pthread_condattr_t = unsafe { std::mem::zeroed() };
                unsafe { libc::pthread_condattr_init(&mut host_attr) };
                if clock != libc::CLOCK_REALTIME {
                    unsafe { libc::pthread_condattr_setclock(&mut host_attr, clock) };
                }
                let rc = unsafe { host_init(cond, &host_attr) };
                unsafe { libc::pthread_condattr_destroy(&mut host_attr) };
                return rc;
            }
        }
        return unsafe { host_init(cond, attr) };
    }

    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    let clock_id = if attr.is_null() {
        PTHREAD_COND_CLOCK_REALTIME
    } else {
        let mut clock_id: c_int = PTHREAD_COND_CLOCK_REALTIME;
        let rc = unsafe { pthread_condattr_getclock(attr, &mut clock_id as *mut c_int) };
        if rc == 0 {
            clock_id
        } else {
            return libc::EINVAL;
        }
    };
    // SAFETY: pointer validated/aligned above and points into caller-owned pthread_cond_t.
    unsafe { core_condvar_init(cond_ptr, clock_id) }
}

/// POSIX `pthread_cond_destroy`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_destroy(cond: *mut libc::pthread_cond_t) -> c_int {
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    if !is_managed_condvar(cond) && !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_destroy) = unsafe { host_pthread_cond_destroy_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_destroy(cond) };
        }
    }
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
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    let managed_condvar = is_managed_condvar(cond);
    let managed_mutex = is_managed_mutex(mutex);
    if !managed_condvar && !managed_mutex && !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // Both condvar and mutex are host-owned: delegate to host pthread_cond_wait.
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_wait) = unsafe { host_pthread_cond_wait_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_wait(cond, mutex) };
        }
    }
    // Guard: managed condvar requires managed mutex (can't mix managed condvar with host mutex).
    if managed_condvar && !managed_mutex {
        return libc::EINVAL;
    }
    // Guard: host condvar with managed mutex is unsupported (bd-79va).
    // We can't pass managed mutex to host (host would misinterpret overlay format),
    // and we can't use native condvar implementation on host condvar (different layout).
    if !managed_condvar && managed_mutex {
        return libc::EINVAL;
    }
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
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    if !is_managed_condvar(cond) && !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_signal) = unsafe { host_pthread_cond_signal_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_signal(cond) };
        }
    }
    // SAFETY: pointer validated/aligned above and points into caller-owned pthread_cond_t.
    unsafe { core_condvar_signal(cond_ptr) }
}

/// POSIX `pthread_cond_broadcast`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_broadcast(cond: *mut libc::pthread_cond_t) -> c_int {
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    if !is_managed_condvar(cond) && !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_broadcast) = unsafe { host_pthread_cond_broadcast_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_broadcast(cond) };
        }
    }
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
    if cond.is_null() || mutex.is_null() || abstime.is_null() {
        return libc::EINVAL;
    }
    if !absolute_timespec_valid(abstime) {
        return libc::EINVAL;
    }
    let managed_condvar = is_managed_condvar(cond);
    let managed_mutex = is_managed_mutex(mutex);
    if !managed_condvar && !managed_mutex && !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // Both condvar and mutex are host-owned: delegate to host pthread_cond_timedwait.
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_timedwait) = unsafe { host_pthread_cond_timedwait_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_timedwait(cond, mutex, abstime) };
        }
    }
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    // Guard: managed condvar requires managed mutex (can't mix managed condvar with host mutex).
    if managed_condvar && !managed_mutex {
        return libc::EINVAL;
    }
    // Guard: host condvar with managed mutex is unsupported (bd-79va).
    // We can't pass managed mutex to host (host would misinterpret overlay format),
    // and we can't use native condvar implementation on host condvar (different layout).
    if !managed_condvar && managed_mutex {
        return libc::EINVAL;
    }
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
    if current_threading_backend() == THREAD_BACKEND_HOST
        && let Some(host_key_create) = unsafe { host_pthread_key_create_fn() }
    {
        return unsafe { host_key_create(key, destructor) };
    }
    let sensitive_context = runtime_policy::bootstrap_passthrough_active()
        || crate::malloc_abi::in_allocator_reentry_context()
        || frankenlibc_membrane::ptr_validator::in_validation_context();
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
    if current_threading_backend() == THREAD_BACKEND_HOST
        && let Some(host_key_delete) = unsafe { host_pthread_key_delete_fn() }
    {
        return unsafe { host_key_delete(key) };
    }
    let sensitive_context = runtime_policy::bootstrap_passthrough_active()
        || crate::malloc_abi::in_allocator_reentry_context()
        || frankenlibc_membrane::ptr_validator::in_validation_context();
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
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getspecific(key: libc::pthread_key_t) -> *mut c_void {
    if current_threading_backend() == THREAD_BACKEND_HOST
        && let Some(host_getspecific) = unsafe { host_pthread_getspecific_fn() }
    {
        return unsafe { host_getspecific(key) };
    }

    let sensitive_context = runtime_policy::bootstrap_passthrough_active()
        || crate::malloc_abi::in_allocator_reentry_context()
        || frankenlibc_membrane::ptr_validator::in_validation_context();
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
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setspecific(
    key: libc::pthread_key_t,
    value: *const c_void,
) -> c_int {
    if current_threading_backend() == THREAD_BACKEND_HOST
        && let Some(host_setspecific) = unsafe { host_pthread_setspecific_fn() }
    {
        return unsafe { host_setspecific(key, value) };
    }

    let sensitive_context = runtime_policy::bootstrap_passthrough_active()
        || crate::malloc_abi::in_allocator_reentry_context()
        || frankenlibc_membrane::ptr_validator::in_validation_context();
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

/// Default stack size for new threads.
/// Override at runtime with `FRANKENLIBC_THREAD_STACK_SIZE` (bytes).
/// glibc uses 8 MiB; our default is 2 MiB as a compact baseline.
fn attr_default_stack_size() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CACHED: AtomicUsize = AtomicUsize::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let size = std::env::var("FRANKENLIBC_THREAD_STACK_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&v| v >= ATTR_MIN_STACK_SIZE)
        .unwrap_or(2 * 1024 * 1024);
    CACHED.store(size, Ordering::Relaxed);
    size
}

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
#[derive(Clone)]
struct ExtendedAttrData {
    affinity: Option<(usize, Vec<u8>)>, // (cpusetsize, raw bytes)
    sigmask: Option<[u8; 128]>,         // sigset_t is 128 bytes on x86_64
}

static EXTENDED_ATTR_REGISTRY: LazyLock<Mutex<HashMap<usize, ExtendedAttrData>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Default thread attributes (for `pthread_getattr_default_np` / `pthread_setattr_default_np`).
static DEFAULT_THREAD_ATTR: LazyLock<Mutex<PthreadAttrDefaults>> =
    LazyLock::new(|| Mutex::new(PthreadAttrDefaults::new()));

#[derive(Clone)]
struct PthreadAttrDefaults {
    detach_state: i32,
    stack_size: usize,
    guard_size: usize,
    inherit_sched: i32,
    sched_policy: i32,
    sched_priority: i32,
    extended: ExtendedAttrData,
}

impl PthreadAttrDefaults {
    fn new() -> Self {
        Self {
            detach_state: libc::PTHREAD_CREATE_JOINABLE,
            stack_size: attr_default_stack_size(),
            guard_size: ATTR_DEFAULT_GUARD_SIZE,
            inherit_sched: PTHREAD_INHERIT_SCHED_VAL,
            sched_policy: 0, // SCHED_OTHER
            sched_priority: 0,
            extended: ExtendedAttrData {
                affinity: None,
                sigmask: None,
            },
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

fn managed_attr_data_ptr(attr: *mut libc::pthread_attr_t) -> Option<*mut PthreadAttrData> {
    let data = attr_data_ptr(attr)?;
    // SAFETY: `data` comes from `attr_data_ptr`, which validated non-null/alignment.
    let is_managed = unsafe { (*data).magic == MANAGED_ATTR_MAGIC };
    is_managed.then_some(data)
}

fn managed_attr_data_ptr_const(
    attr: *const libc::pthread_attr_t,
) -> Option<*const PthreadAttrData> {
    let data = attr_data_ptr_const(attr)?;
    // SAFETY: `data` comes from `attr_data_ptr_const`, which validated non-null/alignment.
    let is_managed = unsafe { (*data).magic == MANAGED_ATTR_MAGIC };
    is_managed.then_some(data)
}

unsafe fn populate_managed_attr_from_host_attr(
    dst: *mut libc::pthread_attr_t,
    host_attr: *const libc::pthread_attr_t,
) -> c_int {
    let Some(data) = managed_attr_data_ptr(dst) else {
        return libc::EINVAL;
    };

    let mut detach_state = libc::PTHREAD_CREATE_JOINABLE;
    let mut stack_size = 0usize;
    let mut guard_size = 0usize;
    let mut stack_addr: *mut c_void = std::ptr::null_mut();
    let mut inherit_sched = 0;
    let mut sched_policy = 0;
    let mut sched_param: libc::sched_param = unsafe { std::mem::zeroed() };

    let Some(getdetachstate) = (unsafe { resolved_pthread_attr_getdetachstate_fn() }) else {
        return libc::ENOSYS;
    };
    let Some(getstacksize) = (unsafe { resolved_pthread_attr_getstacksize_fn() }) else {
        return libc::ENOSYS;
    };
    let Some(getguardsize) = (unsafe { resolved_pthread_attr_getguardsize_fn() }) else {
        return libc::ENOSYS;
    };
    let Some(getstack) = (unsafe { resolved_pthread_attr_getstack_fn() }) else {
        return libc::ENOSYS;
    };
    let Some(getinheritsched) = (unsafe { resolved_pthread_attr_getinheritsched_fn() }) else {
        return libc::ENOSYS;
    };
    let Some(getschedpolicy) = (unsafe { resolved_pthread_attr_getschedpolicy_fn() }) else {
        return libc::ENOSYS;
    };
    let Some(getschedparam) = (unsafe { resolved_pthread_attr_getschedparam_fn() }) else {
        return libc::ENOSYS;
    };

    let mut rc = unsafe { getdetachstate(host_attr, &mut detach_state) };
    if rc == 0 {
        rc = unsafe { getstacksize(host_attr, &mut stack_size) };
    }
    if rc == 0 {
        rc = unsafe { getguardsize(host_attr, &mut guard_size) };
    }
    if rc == 0 {
        rc = unsafe { getstack(host_attr, &mut stack_addr, &mut stack_size) };
    }
    if rc == 0 {
        rc = unsafe { getinheritsched(host_attr, &mut inherit_sched) };
    }
    if rc == 0 {
        rc = unsafe { getschedpolicy(host_attr, &mut sched_policy) };
    }
    if rc == 0 {
        rc = unsafe { getschedparam(host_attr, &mut sched_param) };
    }
    if rc != 0 {
        return rc;
    }

    unsafe {
        (*data).detach_state = detach_state;
        (*data).stack_size = stack_size;
        (*data).guard_size = guard_size;
        (*data).stack_addr = stack_addr as usize;
        (*data).inherit_sched = inherit_sched;
        (*data).sched_policy = sched_policy;
        (*data).sched_priority = sched_param.sched_priority;
        (*data).flags = 0;
    }

    let key = dst as usize;
    let mut reg = EXTENDED_ATTR_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    reg.remove(&key);
    0
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
        (*data).stack_size = attr_default_stack_size();
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
    let Some(data) = managed_attr_data_ptr(attr) else {
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
    let Some(data) = managed_attr_data_ptr(attr) else {
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
    let Some(data) = managed_attr_data_ptr_const(attr) else {
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
    let Some(data) = managed_attr_data_ptr(attr) else {
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
    let Some(data) = managed_attr_data_ptr_const(attr) else {
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
// pthread_mutexattr_t is treated as one managed c_int word.
// Low bits store type plus compact protocol/pshared/robust flags.

const MUTEXATTR_TYPE_MASK: c_int = 0b0000_0011;
const MUTEXATTR_PROTOCOL_MASK: c_int = 0b0000_1100;
const MUTEXATTR_PROTOCOL_SHIFT: u32 = 2;
const MUTEXATTR_PSHARED_BIT: c_int = 1 << 4;
const MUTEXATTR_ROBUST_BIT: c_int = 1 << 5;
const MUTEXATTR_VALID_BIT: c_int = 1 << 6;
const MUTEXATTR_ALLOWED_MASK: c_int = MUTEXATTR_TYPE_MASK
    | MUTEXATTR_PROTOCOL_MASK
    | MUTEXATTR_PSHARED_BIT
    | MUTEXATTR_ROBUST_BIT
    | MUTEXATTR_VALID_BIT;

#[inline]
fn encode_mutexattr(
    type_kind: c_int,
    protocol: c_int,
    pshared: c_int,
    robust: c_int,
) -> Option<c_int> {
    if !(0..=2).contains(&type_kind) {
        return None;
    }
    let protocol_bits = match protocol {
        libc::PTHREAD_PRIO_NONE => 0,
        libc::PTHREAD_PRIO_INHERIT => 1,
        libc::PTHREAD_PRIO_PROTECT => 2,
        _ => return None,
    };
    if pshared != libc::PTHREAD_PROCESS_PRIVATE && pshared != libc::PTHREAD_PROCESS_SHARED {
        return None;
    }
    if robust != libc::PTHREAD_MUTEX_STALLED && robust != libc::PTHREAD_MUTEX_ROBUST {
        return None;
    }

    let mut word = type_kind & MUTEXATTR_TYPE_MASK;
    word |= protocol_bits << MUTEXATTR_PROTOCOL_SHIFT;
    if pshared == libc::PTHREAD_PROCESS_SHARED {
        word |= MUTEXATTR_PSHARED_BIT;
    }
    if robust == libc::PTHREAD_MUTEX_ROBUST {
        word |= MUTEXATTR_ROBUST_BIT;
    }
    word |= MUTEXATTR_VALID_BIT;
    Some(word)
}

#[inline]
fn mutexattr_word_valid(word: c_int) -> bool {
    if word & MUTEXATTR_VALID_BIT == 0 {
        return false;
    }
    if word & !MUTEXATTR_ALLOWED_MASK != 0 {
        return false;
    }
    let type_kind = word & MUTEXATTR_TYPE_MASK;
    let protocol_bits = (word & MUTEXATTR_PROTOCOL_MASK) >> MUTEXATTR_PROTOCOL_SHIFT;
    (0..=2).contains(&type_kind) && (0..=2).contains(&protocol_bits)
}

#[inline]
fn decode_mutexattr_type(word: c_int) -> c_int {
    word & MUTEXATTR_TYPE_MASK
}

#[inline]
fn decode_mutexattr_protocol(word: c_int) -> c_int {
    match (word & MUTEXATTR_PROTOCOL_MASK) >> MUTEXATTR_PROTOCOL_SHIFT {
        0 => libc::PTHREAD_PRIO_NONE,
        1 => libc::PTHREAD_PRIO_INHERIT,
        2 => libc::PTHREAD_PRIO_PROTECT,
        _ => libc::PTHREAD_PRIO_NONE,
    }
}

#[inline]
fn decode_mutexattr_pshared(word: c_int) -> c_int {
    if word & MUTEXATTR_PSHARED_BIT != 0 {
        libc::PTHREAD_PROCESS_SHARED
    } else {
        libc::PTHREAD_PROCESS_PRIVATE
    }
}

#[inline]
fn decode_mutexattr_robust(word: c_int) -> c_int {
    if word & MUTEXATTR_ROBUST_BIT != 0 {
        libc::PTHREAD_MUTEX_ROBUST
    } else {
        libc::PTHREAD_MUTEX_STALLED
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_init(attr: *mut libc::pthread_mutexattr_t) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire)
        && let Some(host_init) = unsafe { host_pthread_mutexattr_init_fn() }
    {
        return unsafe { host_init(attr) };
    }
    let default_word = encode_mutexattr(
        libc::PTHREAD_MUTEX_DEFAULT,
        libc::PTHREAD_PRIO_NONE,
        libc::PTHREAD_PROCESS_PRIVATE,
        libc::PTHREAD_MUTEX_STALLED,
    )
    .unwrap_or(0);
    // SAFETY: attr is non-null; caller owns the memory.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = default_word;
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_destroy(attr: *mut libc::pthread_mutexattr_t) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire)
        && let Some(host_destroy) = unsafe { host_pthread_mutexattr_destroy_fn() }
    {
        return unsafe { host_destroy(attr) };
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
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire)
        && let Some(host_settype) = unsafe { host_pthread_mutexattr_settype_fn() }
    {
        return unsafe { host_settype(attr, kind) };
    }
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    if !mutexattr_word_valid(*word) {
        return libc::EINVAL;
    }
    let Some(next_word) = encode_mutexattr(
        kind,
        decode_mutexattr_protocol(*word),
        decode_mutexattr_pshared(*word),
        decode_mutexattr_robust(*word),
    ) else {
        return libc::EINVAL;
    };
    *word = next_word;
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
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire)
        && let Some(host_gettype) = unsafe { host_pthread_mutexattr_gettype_fn() }
    {
        return unsafe { host_gettype(attr, kind) };
    }
    let word = unsafe { *(attr.cast::<c_int>()) };
    if !mutexattr_word_valid(word) {
        return libc::EINVAL;
    }
    unsafe { *kind = decode_mutexattr_type(word) };
    0
}

// --- Condvar attributes --- native implementation
//
// pthread_condattr_t is treated as one managed c_int word.
// Bit 0 stores CLOCK_MONOTONIC vs CLOCK_REALTIME, bit 1 stores pshared.

const CONDATTR_CLOCK_MONOTONIC_BIT: c_int = 1 << 0;
const CONDATTR_PSHARED_BIT: c_int = 1 << 1;
const CONDATTR_VALID_BIT: c_int = 1 << 2;
const CONDATTR_DESTROYED_SENTINEL: c_int = 0x7fff_ffff;
const CONDATTR_ALLOWED_MASK: c_int =
    CONDATTR_CLOCK_MONOTONIC_BIT | CONDATTR_PSHARED_BIT | CONDATTR_VALID_BIT;

#[inline]
fn encode_condattr(clock_id: libc::clockid_t, pshared: c_int) -> Option<c_int> {
    if clock_id != libc::CLOCK_REALTIME && clock_id != libc::CLOCK_MONOTONIC {
        return None;
    }
    if pshared != libc::PTHREAD_PROCESS_PRIVATE && pshared != libc::PTHREAD_PROCESS_SHARED {
        return None;
    }

    let mut word = 0;
    if clock_id == libc::CLOCK_MONOTONIC {
        word |= CONDATTR_CLOCK_MONOTONIC_BIT;
    }
    if pshared == libc::PTHREAD_PROCESS_SHARED {
        word |= CONDATTR_PSHARED_BIT;
    }
    word |= CONDATTR_VALID_BIT;
    Some(word)
}

#[inline]
fn condattr_word_valid(word: c_int) -> bool {
    if word & CONDATTR_VALID_BIT == 0 {
        return false;
    }
    word & !CONDATTR_ALLOWED_MASK == 0
}

#[inline]
fn decode_condattr_clock(word: c_int) -> libc::clockid_t {
    if word & CONDATTR_CLOCK_MONOTONIC_BIT != 0 {
        libc::CLOCK_MONOTONIC
    } else {
        libc::CLOCK_REALTIME
    }
}

#[inline]
fn decode_condattr_pshared(word: c_int) -> c_int {
    if word & CONDATTR_PSHARED_BIT != 0 {
        libc::PTHREAD_PROCESS_SHARED
    } else {
        libc::PTHREAD_PROCESS_PRIVATE
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_init(attr: *mut libc::pthread_condattr_t) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    let Some(default_word) = encode_condattr(libc::CLOCK_REALTIME, libc::PTHREAD_PROCESS_PRIVATE)
    else {
        return libc::EINVAL;
    };
    // SAFETY: attr is non-null; caller owns the memory.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = default_word;
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_destroy(attr: *mut libc::pthread_condattr_t) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null; caller owns the memory.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = CONDATTR_DESTROYED_SENTINEL;
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
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    if !condattr_word_valid(*word) {
        return libc::EINVAL;
    }
    let pshared = decode_condattr_pshared(*word);
    let Some(next_word) = encode_condattr(clock_id, pshared) else {
        return libc::EINVAL;
    };
    *word = next_word;
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
    let word = unsafe { *(attr.cast::<c_int>()) };
    if word == CONDATTR_DESTROYED_SENTINEL {
        return libc::EINVAL;
    }
    if condattr_word_valid(word) {
        unsafe { *clock_id = decode_condattr_clock(word) };
        return 0;
    }
    if let Some(host_getclock) = unsafe { host_pthread_condattr_getclock_fn() } {
        return unsafe { host_getclock(attr, clock_id) };
    }
    libc::EINVAL
}

// --- Rwlock attributes --- native implementation
//
// pthread_rwlockattr_t is 8 bytes. We store the kind (reader/writer preference)
// in the first c_int. Default is PREFER_READER.

const RWLOCKATTR_VALID_BIT: c_int = 1 << 8;
const RWLOCKATTR_PSHARED_BIT: c_int = 1 << 0;

fn rwlockattr_word_valid(word: c_int) -> bool {
    word & RWLOCKATTR_VALID_BIT != 0
}

fn encode_rwlockattr(pshared: c_int) -> Option<c_int> {
    if pshared != libc::PTHREAD_PROCESS_PRIVATE && pshared != libc::PTHREAD_PROCESS_SHARED {
        return None;
    }
    let mut word = RWLOCKATTR_VALID_BIT;
    if pshared == libc::PTHREAD_PROCESS_SHARED {
        word |= RWLOCKATTR_PSHARED_BIT;
    }
    Some(word)
}

fn decode_rwlockattr_pshared(word: c_int) -> c_int {
    if word & RWLOCKATTR_PSHARED_BIT != 0 {
        libc::PTHREAD_PROCESS_SHARED
    } else {
        libc::PTHREAD_PROCESS_PRIVATE
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_init(attr: *mut libc::pthread_rwlockattr_t) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    let Some(default_word) = encode_rwlockattr(libc::PTHREAD_PROCESS_PRIVATE) else {
        return libc::EINVAL;
    };
    // SAFETY: attr is non-null; caller owns the memory.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = default_word;
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

fn is_managed_thread_handle(thread: libc::pthread_t) -> bool {
    let thread_key = thread as usize;
    if THREAD_HANDLE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&thread_key)
    {
        return true;
    }
    MANAGED_THREAD_TOMBSTONES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&thread_key)
}

fn is_detached_thread_handle(thread: libc::pthread_t) -> bool {
    DETACHED_THREAD_TOMBSTONES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&(thread as usize))
}

fn current_cancel_key() -> usize {
    native_pthread_self() as usize
}

fn current_thread_is_managed() -> bool {
    let tid = core_self_tid();
    tid > 0 && core_handle_for_tid(tid).is_some()
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

    // Host-backed pthread_create remains the default. Those pthread_t values are
    // opaque glibc handles, so our native kill/TID path cannot validate or cancel
    // them reliably. Delegate non-self, non-managed threads back to host pthread.
    if !force_native_threading_enabled()
        && !is_managed_thread_handle(thread)
        && let Some(host_cancel) = crate::host_resolve::host_pthread_cancel_raw()
    {
        return unsafe { host_cancel(thread) };
    }

    // Validate that the target looks alive before enqueuing a cancel request.
    // Signal 0 performs existence checking without delivering a signal.
    let liveness = unsafe { pthread_kill(thread, 0) };
    if liveness != 0 {
        return liveness;
    }

    let thread_key = pthread_handle_key(thread);
    set_cancellation_pending(thread_key, true);

    // If cancelling ourselves in async mode, act on it immediately.
    if thread_key == current_cancel_key()
        && cancel_enabled_for_current_thread()
        && cancel_async_for_current_thread()
    {
        unsafe { pthread_testcancel() };
    }

    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setcancelstate(state: c_int, oldstate: *mut c_int) -> c_int {
    if state != PTHREAD_CANCEL_ENABLE_STATE && state != PTHREAD_CANCEL_DISABLE_STATE {
        return libc::EINVAL;
    }
    if !force_native_threading_enabled()
        && !current_thread_is_managed()
        && let Some(host_setcancelstate) = crate::host_resolve::host_pthread_setcancelstate_raw()
    {
        return unsafe { host_setcancelstate(state, oldstate) };
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
        unsafe { pthread_testcancel() };
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setcanceltype(typ: c_int, oldtype: *mut c_int) -> c_int {
    if typ != PTHREAD_CANCEL_DEFERRED_TYPE && typ != PTHREAD_CANCEL_ASYNCHRONOUS_TYPE {
        return libc::EINVAL;
    }
    if !force_native_threading_enabled()
        && !current_thread_is_managed()
        && let Some(host_setcanceltype) = crate::host_resolve::host_pthread_setcanceltype_raw()
    {
        return unsafe { host_setcanceltype(typ, oldtype) };
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
        unsafe { pthread_testcancel() };
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_testcancel() {
    if !force_native_threading_enabled()
        && !current_thread_is_managed()
        && let Some(host_testcancel) = crate::host_resolve::host_pthread_testcancel_raw()
    {
        unsafe { host_testcancel() };
        return;
    }
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
    if attr.is_null() {
        return libc::EINVAL;
    }
    let force_native = force_native_threading_enabled();
    if !force_native
        && !is_managed_thread_handle(thread)
        && let Some(host_addr) = crate::host_resolve::resolve_host_symbol_raw("pthread_getattr_np")
    {
        let host_getattr: HostPthreadGetattrFn = unsafe { core::mem::transmute(host_addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
        let mut host_attr: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
        let rc = unsafe { host_getattr(thread, &mut host_attr) };
        if rc != 0 {
            return rc;
        }
        let init_rc = unsafe { pthread_attr_init(attr) };
        if init_rc != 0 {
            if let Some(attr_destroy) = unsafe { resolved_pthread_attr_destroy_fn() } {
                let _ = unsafe { attr_destroy(&mut host_attr) };
            }
            return init_rc;
        }
        let translate_rc = unsafe { populate_managed_attr_from_host_attr(attr, &host_attr) };
        let destroy_rc = if let Some(attr_destroy) = unsafe { resolved_pthread_attr_destroy_fn() } {
            unsafe { attr_destroy(&mut host_attr) }
        } else {
            0
        };
        return if translate_rc != 0 {
            translate_rc
        } else if destroy_rc != 0 {
            destroy_rc
        } else {
            0
        };
    }

    // Initialize the attr struct with defaults, then fill in thread-specific info.
    let ret = unsafe { pthread_attr_init(attr) };
    if ret != 0 {
        return ret;
    }
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    // Look up managed thread metadata captured at native create time.
    let thread_key = thread as usize;
    let registry = THREAD_HANDLE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(record) = registry.get(&thread_key) {
        let handle_ptr = record.handle_raw as *mut ThreadHandle;
        // SAFETY: registry only stores live handles from core_create_thread.
        let state = unsafe { (*handle_ptr).state.load(Ordering::Acquire) };
        let detach_state = if state == THREAD_DETACHED {
            libc::PTHREAD_CREATE_DETACHED
        } else {
            record.detach_state
        };
        // SAFETY: pointer is non-null and aligned; we initialized it above.
        unsafe {
            (*data).detach_state = detach_state;
            (*data).stack_size = record.stack_size;
            (*data).guard_size = ATTR_DEFAULT_GUARD_SIZE;
            (*data).stack_addr = (*handle_ptr).stack_base + ATTR_DEFAULT_GUARD_SIZE;
        }
        return 0;
    }
    drop(registry);

    if is_managed_thread_handle(thread) && resolve_thread_tid(thread).is_some() {
        let handle_ptr = thread as *mut ThreadHandle;
        // SAFETY: a managed detached thread keeps its handle alive until it
        // exits and self-cleans. `resolve_thread_tid(thread).is_some()` above
        // established that the thread still appears live, so the handle fields
        // remain readable here.
        let state = unsafe { (*handle_ptr).state.load(Ordering::Acquire) };
        // SAFETY: same liveness argument as above.
        let stack_total_size = unsafe { (*handle_ptr).stack_total_size };
        let stack_base = unsafe { (*handle_ptr).stack_base };
        let detach_state = if state == THREAD_DETACHED {
            libc::PTHREAD_CREATE_DETACHED
        } else {
            libc::PTHREAD_CREATE_JOINABLE
        };
        unsafe {
            (*data).detach_state = detach_state;
            (*data).stack_size = stack_total_size.saturating_sub(ATTR_DEFAULT_GUARD_SIZE);
            (*data).guard_size = ATTR_DEFAULT_GUARD_SIZE;
            (*data).stack_addr = stack_base + ATTR_DEFAULT_GUARD_SIZE;
        }
        return 0;
    }

    if let Some(self_handle) = core_handle_for_tid(core_self_tid())
        && self_handle == thread as *mut ThreadHandle
    {
        let handle_ptr = self_handle;
        // SAFETY: `self_handle` comes from core TLS lookup for the current thread.
        let state = unsafe { (*handle_ptr).state.load(Ordering::Acquire) };
        let detach_state = if state == THREAD_DETACHED {
            libc::PTHREAD_CREATE_DETACHED
        } else {
            libc::PTHREAD_CREATE_JOINABLE
        };
        // SAFETY: `handle_ptr` is the current thread's live handle.
        let stack_total_size = unsafe { (*handle_ptr).stack_total_size };
        let stack_base = unsafe { (*handle_ptr).stack_base };
        unsafe {
            (*data).detach_state = detach_state;
            (*data).stack_size = stack_total_size.saturating_sub(ATTR_DEFAULT_GUARD_SIZE);
            (*data).guard_size = ATTR_DEFAULT_GUARD_SIZE;
            (*data).stack_addr = stack_base + ATTR_DEFAULT_GUARD_SIZE;
        }
        return 0;
    }

    // Fallback: parse /proc/self/task/<tid>/maps to discover stack boundaries.
    // This handles the main thread (not created by pthread_create) and any
    // thread whose handle we can't locate in our registries.
    let probe_tid = if thread == native_pthread_self() {
        core_self_tid()
    } else {
        resolve_thread_tid(thread).unwrap_or(-1)
    };
    if probe_tid > 0
        && let Some((stack_start, stack_size)) = stack_bounds_from_proc_maps(probe_tid)
    {
        // The main thread is always joinable (it cannot be detached).
        unsafe {
            (*data).detach_state = libc::PTHREAD_CREATE_JOINABLE;
            (*data).stack_size = stack_size.saturating_sub(ATTR_DEFAULT_GUARD_SIZE);
            (*data).guard_size = ATTR_DEFAULT_GUARD_SIZE;
            (*data).stack_addr = stack_start + ATTR_DEFAULT_GUARD_SIZE;
        }
        return 0;
    }

    libc::ESRCH
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
    let ret = unsafe {
        syscall4(
            libc::SYS_futex as usize,
            addr as *const AtomicU32 as *const u32 as usize,
            (libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG) as usize,
            expected as usize,
            std::ptr::null::<libc::timespec>() as usize,
        )
    };
    match syscall_result(ret) {
        Ok(v) => v as c_int,
        Err(errno) => {
            unsafe { set_abi_errno(errno) };
            -1
        }
    }
}

fn futex_wake_u32(addr: &AtomicU32, count: i32) -> c_int {
    // SAFETY: Linux futex syscall with valid userspace address.
    let ret = unsafe {
        syscall3(
            libc::SYS_futex as usize,
            addr as *const AtomicU32 as *const u32 as usize,
            (libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG) as usize,
            count as usize,
        )
    };
    match syscall_result(ret) {
        Ok(v) => v as c_int,
        Err(errno) => {
            unsafe { set_abi_errno(errno) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrier_init(
    barrier: *mut c_void,
    attr: *const c_void,
    count: libc::c_uint,
) -> c_int {
    if count == 0 {
        return libc::EINVAL;
    }
    if !attr.is_null() {
        let word = unsafe { *(attr.cast::<c_int>()) };
        if word & BARRIERATTR_VALID_BIT == 0 {
            return libc::EINVAL;
        }
        if (word & !BARRIERATTR_VALID_BIT) != libc::PTHREAD_PROCESS_PRIVATE {
            return libc::EINVAL;
        }
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
    let (len, terminated) = unsafe {
        crate::util::scan_c_string(name, crate::malloc_abi::known_remaining(name as usize))
    };
    if !terminated {
        return libc::EFAULT;
    }
    if len > 15 {
        return libc::ERANGE;
    }
    if _thread != native_pthread_self() {
        if !force_native_threading_enabled()
            && !is_managed_thread_handle(_thread)
            && let Some(host_setname) = crate::host_resolve::host_pthread_setname_np_raw()
        {
            return unsafe { host_setname(_thread, name) };
        }
        let Some(tid) = resolve_thread_tid(_thread) else {
            return libc::ESRCH;
        };
        // SAFETY: We already validated name is terminated (line 4644-4647).
        let name_cstr = unsafe { std::ffi::CStr::from_ptr(name) };
        return set_other_thread_name_via_procfs(tid, name_cstr);
    }
    // SAFETY: prctl(PR_SET_NAME) sets the calling thread's name.
    let ret = unsafe {
        syscall5(
            libc::SYS_prctl as usize,
            PR_SET_NAME as usize,
            name as usize,
            0,
            0,
            0,
        )
    };
    match syscall_result(ret) {
        Ok(_) => 0,
        Err(errno) => errno,
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
        if !force_native_threading_enabled()
            && !is_managed_thread_handle(_thread)
            && let Some(host_getname) = crate::host_resolve::host_pthread_getname_np_raw()
        {
            return unsafe { host_getname(_thread, name, len) };
        }
        let Some(tid) = resolve_thread_tid(_thread) else {
            return libc::ESRCH;
        };
        return get_other_thread_name_via_procfs(tid, name, len);
    }
    // SAFETY: prctl(PR_GET_NAME) reads the calling thread's name into a buffer.
    let ret = unsafe {
        syscall5(
            libc::SYS_prctl as usize,
            PR_GET_NAME as usize,
            name as usize,
            0,
            0,
            0,
        )
    };
    match syscall_result(ret) {
        Ok(_) => 0,
        Err(errno) => errno,
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
    let Some(data) = managed_attr_data_ptr_const(attr) else {
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
    let Some(data) = managed_attr_data_ptr(attr) else {
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
    if managed_attr_data_ptr_const(attr).is_none() || cpuset.is_null() || cpusetsize == 0 {
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
    let Some(data) = managed_attr_data_ptr(attr) else {
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
    let Some(data) = managed_attr_data_ptr_const(attr) else {
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
    let Some(data) = managed_attr_data_ptr(attr) else {
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
    let Some(data) = managed_attr_data_ptr_const(attr) else {
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
    let Some(data) = managed_attr_data_ptr(attr) else {
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
    let Some(data) = managed_attr_data_ptr_const(attr) else {
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
    let Some(data) = managed_attr_data_ptr(attr) else {
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
    if managed_attr_data_ptr_const(attr).is_none() || scope.is_null() {
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
    if managed_attr_data_ptr(attr).is_none() {
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
    let Some(data) = managed_attr_data_ptr_const(attr) else {
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
    let Some(data) = managed_attr_data_ptr(attr) else {
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
/// Native implementation using the managed attr overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getstackaddr(
    attr: *const libc::pthread_attr_t,
    stackaddr: *mut *mut c_void,
) -> c_int {
    let Some(data) = managed_attr_data_ptr_const(attr) else {
        return libc::EINVAL;
    };
    if stackaddr.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: pointers are non-null and aligned.
    unsafe { *stackaddr = (*data).stack_addr as *mut c_void };
    0
}

/// Deprecated `pthread_attr_setstackaddr` — set stack address.
/// Native implementation using the managed attr overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstackaddr(
    attr: *mut libc::pthread_attr_t,
    stackaddr: *mut c_void,
) -> c_int {
    let Some(data) = managed_attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    if stackaddr.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: pointer is non-null and aligned.
    unsafe { (*data).stack_addr = stackaddr as usize };
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
    *word = BARRIERATTR_VALID_BIT | libc::PTHREAD_PROCESS_PRIVATE;
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

const BARRIERATTR_VALID_BIT: c_int = 1 << 8;

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
    let word = unsafe { *(attr.cast::<c_int>()) };
    if word & BARRIERATTR_VALID_BIT == 0 {
        return libc::EINVAL;
    }
    unsafe {
        *pshared = word & !BARRIERATTR_VALID_BIT;
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
    if *word & BARRIERATTR_VALID_BIT == 0 {
        return libc::EINVAL;
    }
    *word = BARRIERATTR_VALID_BIT | pshared;
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
    let word = unsafe { *(attr.cast::<c_int>()) };
    if !condattr_word_valid(word) {
        return libc::EINVAL;
    }
    unsafe { *pshared = decode_condattr_pshared(word) };
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
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    if !condattr_word_valid(*word) {
        return libc::EINVAL;
    }
    let clock_id = decode_condattr_clock(*word);
    let Some(next_word) = encode_condattr(clock_id, pshared) else {
        return libc::EINVAL;
    };
    *word = next_word;
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
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire)
        && let Some(host_getprotocol) = unsafe { host_pthread_mutexattr_getprotocol_fn() }
    {
        return unsafe { host_getprotocol(attr, protocol) };
    }
    let word = unsafe { *(attr.cast::<c_int>()) };
    if !mutexattr_word_valid(word) {
        return libc::EINVAL;
    }
    unsafe { *protocol = decode_mutexattr_protocol(word) };
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
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire)
        && let Some(host_setprotocol) = unsafe { host_pthread_mutexattr_setprotocol_fn() }
    {
        return unsafe { host_setprotocol(attr, protocol) };
    }
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    if !mutexattr_word_valid(*word) {
        return libc::EINVAL;
    }
    let Some(next_word) = encode_mutexattr(
        decode_mutexattr_type(*word),
        protocol,
        decode_mutexattr_pshared(*word),
        decode_mutexattr_robust(*word),
    ) else {
        return libc::EINVAL;
    };
    *word = next_word;
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
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire)
        && let Some(host_getpshared) = unsafe { host_pthread_mutexattr_getpshared_fn() }
    {
        return unsafe { host_getpshared(attr, pshared) };
    }
    let word = unsafe { *(attr.cast::<c_int>()) };
    if !mutexattr_word_valid(word) {
        return libc::EINVAL;
    }
    unsafe { *pshared = decode_mutexattr_pshared(word) };
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
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire)
        && let Some(host_setpshared) = unsafe { host_pthread_mutexattr_setpshared_fn() }
    {
        return unsafe { host_setpshared(attr, pshared) };
    }
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    if !mutexattr_word_valid(*word) {
        return libc::EINVAL;
    }
    let Some(next_word) = encode_mutexattr(
        decode_mutexattr_type(*word),
        decode_mutexattr_protocol(*word),
        pshared,
        decode_mutexattr_robust(*word),
    ) else {
        return libc::EINVAL;
    };
    *word = next_word;
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
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire)
        && let Some(host_getrobust) = unsafe { host_pthread_mutexattr_getrobust_fn() }
    {
        return unsafe { host_getrobust(attr, robust) };
    }
    let word = unsafe { *(attr.cast::<c_int>()) };
    if !mutexattr_word_valid(word) {
        return libc::EINVAL;
    }
    unsafe { *robust = decode_mutexattr_robust(word) };
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
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire)
        && let Some(host_setrobust) = unsafe { host_pthread_mutexattr_setrobust_fn() }
    {
        return unsafe { host_setrobust(attr, robust) };
    }
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    if !mutexattr_word_valid(*word) {
        return libc::EINVAL;
    }
    let Some(next_word) = encode_mutexattr(
        decode_mutexattr_type(*word),
        decode_mutexattr_protocol(*word),
        decode_mutexattr_pshared(*word),
        robust,
    ) else {
        return libc::EINVAL;
    };
    *word = next_word;
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
    let word = unsafe { *(attr.cast::<c_int>()) };
    if !rwlockattr_word_valid(word) {
        return libc::EINVAL;
    }
    unsafe {
        *pshared = decode_rwlockattr_pshared(word);
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
    let word = unsafe { *(attr.cast::<c_int>()) };
    if !rwlockattr_word_valid(word) {
        return libc::EINVAL;
    }
    let Some(next_word) = encode_rwlockattr(pshared) else {
        return libc::EINVAL;
    };
    // SAFETY: attr is non-null.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = next_word;
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
    if !absolute_timespec_valid(abstime) {
        return libc::EINVAL;
    }
    let force_native = FORCE_NATIVE_MUTEX.load(Ordering::Acquire);
    if !is_managed_mutex(mutex) {
        if !force_native && let Some(host_timedlock) = unsafe { host_pthread_mutex_timedlock_fn() }
        {
            return unsafe { host_timedlock(mutex, abstime) };
        }
        return libc::EINVAL;
    }
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    // SAFETY: alignment validated by `mutex_word_ptr`.
    let word = unsafe { &*word_ptr };

    match read_mutex_type(mutex) {
        PTHREAD_MUTEX_RECURSIVE_TYPE => {
            let self_tid = core_self_tid();
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                if owner.load(Ordering::Acquire) == self_tid
                    && self_tid != MUTEX_NO_OWNER
                    && let Some(count_ptr) = mutex_lock_count_ptr(mutex)
                {
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
            let rc = timed_futex_lock_normal(word, abstime);
            if rc != 0 {
                return rc;
            }
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
            return 0;
        }
        PTHREAD_MUTEX_ERRORCHECK_TYPE => {
            let self_tid = core_self_tid();
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                if owner.load(Ordering::Acquire) == self_tid && self_tid != MUTEX_NO_OWNER {
                    return libc::EDEADLK;
                }
            }
            let rc = timed_futex_lock_normal(word, abstime);
            if rc != 0 {
                return rc;
            }
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                owner.store(self_tid, Ordering::Release);
            }
            return 0;
        }
        _ => {}
    }

    timed_futex_lock_normal(word, abstime)
}

fn timed_futex_lock_normal(word: &AtomicI32, abstime: *const libc::timespec) -> c_int {
    if word
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        return 0;
    }

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
            let errno = unsafe { std::ptr::read_volatile(crate::errno_abi::__errno_location()) };
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
    let real_deadline = match clock_convert_to_realtime(clockid, abstime) {
        Ok(deadline) => deadline,
        Err(err) => return err,
    };
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
    if !absolute_timespec_valid(abstime) {
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
    if !absolute_timespec_valid(abstime) {
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
    let real_deadline = match clock_convert_to_realtime(clockid, abstime) {
        Ok(deadline) => deadline,
        Err(err) => return err,
    };
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
    let real_deadline = match clock_convert_to_realtime(clockid, abstime) {
        Ok(deadline) => deadline,
        Err(err) => return err,
    };
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
    if !absolute_timespec_valid(abstime) {
        return libc::EINVAL;
    }
    let managed_condvar = is_managed_condvar(cond);
    let managed_mutex = is_managed_mutex(mutex);
    if !managed_condvar && !managed_mutex && !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // Both condvar and mutex are host-owned: delegate to host pthread_cond_clockwait.
        if let Some(host_addr) =
            crate::host_resolve::resolve_host_symbol_raw("pthread_cond_clockwait")
        {
            let host_clockwait: unsafe extern "C" fn(
                *mut libc::pthread_cond_t,
                *mut libc::pthread_mutex_t,
                c_int,
                *const libc::timespec,
            ) -> c_int = unsafe { core::mem::transmute(host_addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
            return unsafe { host_clockwait(cond, mutex, clockid, abstime) };
        }
        if clockid == libc::CLOCK_REALTIME {
            // Still host-owned: pthread_cond_timedwait will also delegate to host.
            return unsafe { pthread_cond_timedwait(cond, mutex, abstime) };
        }
    }
    // Guard: if condvar is host-managed but mutex is managed, we need native implementation.
    // We cannot delegate to host because it would misinterpret our mutex overlay (bd-79va).
    if !managed_condvar && managed_mutex {
        // Fall through to error - can't use native condvar impl with host condvar.
        // This case requires the host condvar but we can't pass managed mutex to it.
        // Return EINVAL since we can't satisfy the request.
        return libc::EINVAL;
    }
    if !managed_condvar {
        return libc::EINVAL;
    }
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    let cond_clock =
        condvar_clock_to_libc(unsafe { (&*cond_ptr).clock_id.load(Ordering::Acquire) as i32 });
    let converted_deadline;
    let effective_deadline = if cond_clock == clockid {
        abstime
    } else {
        converted_deadline = match clock_convert_between(clockid, cond_clock, abstime) {
            Ok(deadline) => deadline,
            Err(err) => return err,
        };
        &converted_deadline
    };
    unsafe { pthread_cond_timedwait(cond, mutex, effective_deadline) }
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
    if !force_native_threading_enabled()
        && !is_managed_thread_handle(thread)
        && let Some(host_addr) =
            crate::host_resolve::resolve_host_symbol_raw("pthread_timedjoin_np")
    {
        let host_timedjoin: unsafe extern "C" fn(
            libc::pthread_t,
            *mut *mut c_void,
            *const libc::timespec,
        ) -> c_int = unsafe { core::mem::transmute(host_addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
        return unsafe { host_timedjoin(thread, retval, abstime) };
    }
    if abstime.is_null() {
        // NULL timeout = blocking join.
        return unsafe { native_pthread_join(thread, retval) };
    }
    if !absolute_timespec_valid(abstime) {
        return libc::EINVAL;
    }
    let thread_key = thread as usize;
    let handle_ptr = thread as *mut ThreadHandle;
    let my_tid = core_self_tid();

    // Self-join detection.
    if let Some(my_handle) = core_handle_for_tid(my_tid)
        && handle_ptr == my_handle
    {
        return libc::EDEADLK;
    }
    if my_tid > 0 && thread_key == my_tid as usize {
        return libc::EDEADLK;
    }

    // Peek at state without removing from registry.
    let handle_ptr = {
        let registry = THREAD_HANDLE_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match registry.get(&thread_key) {
            Some(record) => {
                let hp = record.handle_raw as *mut ThreadHandle;
                let state = unsafe { (*hp).state.load(Ordering::Acquire) };
                if state == THREAD_DETACHED || state == THREAD_JOINED {
                    return libc::EINVAL;
                }
                hp
            }
            None => {
                if is_detached_thread_handle(thread) {
                    return libc::EINVAL;
                }
                return libc::ESRCH;
            }
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
        let now = match clock_gettime_checked(libc::CLOCK_REALTIME) {
            Ok(now) => now,
            Err(errno) => return errno,
        };
        if now.tv_sec > unsafe { (*abstime).tv_sec }
            || (now.tv_sec == unsafe { (*abstime).tv_sec }
                && now.tv_nsec >= unsafe { (*abstime).tv_nsec })
        {
            return libc::ETIMEDOUT;
        }
        // Futex wait on the tid field with timeout.
        // SAFETY: handle_ptr is valid (from registry lookup above).
        let tid_ptr = unsafe { &(*handle_ptr).tid };
        // CLONE_CHILD_CLEARTID wakes joiners with a non-private futex op.
        let ret = futex_wait_timed_shared(tid_ptr, tid, abstime);
        if ret < 0 {
            let errno = unsafe { std::ptr::read_volatile(crate::errno_abi::__errno_location()) };
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
    if !force_native_threading_enabled()
        && !is_managed_thread_handle(thread)
        && let Some(host_addr) = crate::host_resolve::resolve_host_symbol_raw("pthread_tryjoin_np")
    {
        let host_tryjoin: unsafe extern "C" fn(libc::pthread_t, *mut *mut c_void) -> c_int =
            unsafe { core::mem::transmute(host_addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
        return unsafe { host_tryjoin(thread, retval) };
    }
    let thread_key = thread as usize;
    let handle_ptr = thread as *mut ThreadHandle;
    let my_tid = core_self_tid();

    if let Some(my_handle) = core_handle_for_tid(my_tid)
        && handle_ptr == my_handle
    {
        return libc::EDEADLK;
    }
    if my_tid > 0 && thread_key == my_tid as usize {
        return libc::EDEADLK;
    }

    // Check if thread is finished without removing from registry.
    {
        let registry = THREAD_HANDLE_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match registry.get(&thread_key) {
            Some(record) => {
                let handle_ptr = record.handle_raw as *mut ThreadHandle;
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
            None => {
                if is_detached_thread_handle(thread) {
                    return libc::EINVAL;
                }
                return libc::ESRCH;
            }
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
    if !force_native_threading_enabled()
        && !is_managed_thread_handle(thread)
        && let Some(host_addr) =
            crate::host_resolve::resolve_host_symbol_raw("pthread_clockjoin_np")
    {
        let host_clockjoin: unsafe extern "C" fn(
            libc::pthread_t,
            *mut *mut c_void,
            c_int,
            *const libc::timespec,
        ) -> c_int = unsafe { core::mem::transmute(host_addr) }; // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
        return unsafe { host_clockjoin(thread, retval, clockid, abstime) };
    }
    if abstime.is_null() {
        return unsafe { native_pthread_join(thread, retval) };
    }
    if clockid == libc::CLOCK_REALTIME {
        return unsafe { pthread_timedjoin_np(thread, retval, abstime) };
    }
    // Convert from the specified clock to CLOCK_REALTIME.
    let real_deadline = match clock_convert_to_realtime(clockid, abstime) {
        Ok(deadline) => deadline,
        Err(err) => return err,
    };
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
    if !force_native_threading_enabled()
        && thread != native_pthread_self()
        && !is_managed_thread_handle(thread)
        && let Some(host_kill) = crate::host_resolve::host_pthread_kill_raw()
    {
        return unsafe { host_kill(thread, sig) };
    }
    match resolve_thread_tid(thread) {
        Some(tid) => {
            let pid = match syscall_result(unsafe { syscall0(libc::SYS_getpid as usize) }) {
                Ok(pid) => pid as i32,
                Err(errno) => return errno,
            };
            let ret = unsafe {
                syscall3(
                    libc::SYS_tgkill as usize,
                    pid as usize,
                    tid as usize,
                    sig as usize,
                )
            };
            match syscall_result(ret) {
                Ok(_) => 0,
                Err(errno) => errno,
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
    if !force_native_threading_enabled()
        && thread != native_pthread_self()
        && !is_managed_thread_handle(thread)
        && let Some(host_sigqueue) = crate::host_resolve::host_pthread_sigqueue_raw()
    {
        return unsafe { host_sigqueue(thread, sig, value) };
    }
    match resolve_thread_tid(thread) {
        Some(tid) => {
            let pid = match syscall_result(unsafe { syscall0(libc::SYS_getpid as usize) }) {
                Ok(pid) => pid as i32,
                Err(errno) => return errno,
            };
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            info.si_signo = sig;
            info.si_errno = 0;
            info.si_code = libc::SI_QUEUE;
            // Encode sender identity and queued payload using the Linux queue
            // siginfo layout instead of hard-coded byte offsets.
            let info_words = (&mut info as *mut libc::siginfo_t).cast::<u32>();
            let caller_uid = match syscall_result(unsafe { syscall0(libc::SYS_getuid as usize) }) {
                Ok(uid) => uid as u32,
                Err(errno) => return errno,
            };
            let value_bits = value.sival_ptr as usize as u64;
            unsafe {
                *info_words.add(3) = pid as u32;
                *info_words.add(4) = caller_uid;
                if std::mem::size_of::<usize>() > 4 {
                    // Linux aligns `sigval_t` to 8 bytes inside the SI_QUEUE
                    // payload, leaving one 32-bit hole after `si_uid`.
                    *info_words.add(6) = value_bits as u32;
                    *info_words.add(7) = (value_bits >> 32) as u32;
                } else {
                    *info_words.add(5) = value_bits as u32;
                }
            }
            let ret = unsafe {
                syscall4(
                    libc::SYS_rt_tgsigqueueinfo as usize,
                    pid as usize,
                    tid as usize,
                    sig as usize,
                    &info as *const libc::siginfo_t as usize,
                )
            };
            match syscall_result(ret) {
                Ok(_) => 0,
                Err(errno) => errno,
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
    if !force_native_threading_enabled()
        && thread != native_pthread_self()
        && !is_managed_thread_handle(thread)
        && let Some(host_getaffinity) = crate::host_resolve::host_pthread_getaffinity_np_raw()
    {
        return unsafe { host_getaffinity(thread, cpusetsize, cpuset) };
    }
    match resolve_thread_tid(thread) {
        Some(tid) => {
            let ret = unsafe {
                syscall3(
                    libc::SYS_sched_getaffinity as usize,
                    tid as usize,
                    cpusetsize,
                    cpuset as usize,
                )
            };
            match syscall_result(ret) {
                Ok(ret) => {
                    // Kernel may return fewer bytes than requested; zero the rest.
                    let filled = ret;
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
                Err(errno) => errno,
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
    if !force_native_threading_enabled()
        && thread != native_pthread_self()
        && !is_managed_thread_handle(thread)
        && let Some(host_setaffinity) = crate::host_resolve::host_pthread_setaffinity_np_raw()
    {
        return unsafe { host_setaffinity(thread, cpusetsize, cpuset) };
    }
    match resolve_thread_tid(thread) {
        Some(tid) => {
            let ret = unsafe {
                syscall3(
                    libc::SYS_sched_setaffinity as usize,
                    tid as usize,
                    cpusetsize,
                    cpuset as usize,
                )
            };
            match syscall_result(ret) {
                Ok(_) => 0,
                Err(errno) => errno,
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
pub unsafe extern "C" fn pthread_setconcurrency(level: c_int) -> c_int {
    if level < 0 {
        return libc::EINVAL;
    }
    PTHREAD_CONCURRENCY_LEVEL.store(level, Ordering::Release);
    0
}

/// Obsolete POSIX `pthread_getconcurrency` — get concurrency level.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getconcurrency() -> c_int {
    PTHREAD_CONCURRENCY_LEVEL.load(Ordering::Acquire)
}

/// Deprecated `pthread_yield` — yield processor (GNU extension, same as sched_yield).
///
/// Native implementation using `sched_yield(2)` syscall.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_yield() -> c_int {
    let ret = unsafe { syscall0(libc::SYS_sched_yield as usize) };
    match syscall_result(ret) {
        Ok(_) => 0,
        Err(errno) => {
            unsafe { set_abi_errno(errno) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Thread lifecycle extensions
// ---------------------------------------------------------------------------

/// POSIX `pthread_exit` — terminate calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_exit(retval: *mut c_void) -> ! {
    let tid = core_self_tid();
    if let Some(handle_ptr) = core_handle_for_tid(tid) {
        unsafe { core_exit_current_thread(handle_ptr, retval as usize) };
    }

    if !force_native_threading_enabled()
        && let Some(host_exit) = crate::host_resolve::host_pthread_exit_raw()
    {
        unsafe { host_exit(retval) };
    }

    unsafe { syscall1(libc::SYS_exit as usize, 0) };
    loop {
        std::hint::spin_loop();
    }
}

/// GNU `pthread_getcpuclockid` — get CPU-time clock for a thread.
///
/// Native implementation using the Linux kernel per-thread CPUCLOCK formula:
/// `clockid = (~tid << 3) | 6`
/// (`CPUCLOCK_SCHED | CPUCLOCK_PERTHREAD_MASK` for thread CPU time).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getcpuclockid(
    thread: libc::pthread_t,
    clockid: *mut libc::clockid_t,
) -> c_int {
    if clockid.is_null() {
        return libc::EINVAL;
    }
    if !force_native_threading_enabled()
        && thread != native_pthread_self()
        && !is_managed_thread_handle(thread)
        && let Some(host_getcpuclockid) = crate::host_resolve::host_pthread_getcpuclockid_raw()
    {
        return unsafe { host_getcpuclockid(thread, clockid) };
    }
    match resolve_thread_tid(thread) {
        Some(tid) => {
            // Linux per-thread CPUCLOCK formula:
            // (~tid << 3) | (CPUCLOCK_SCHED(2) | CPUCLOCK_PERTHREAD_MASK(4))
            let cid: libc::clockid_t = (!tid as libc::clockid_t) << 3 | 6;
            // Validate that the clock is usable via clock_getres.
            let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                syscall2(
                    libc::SYS_clock_getres as usize,
                    cid as usize,
                    &mut ts as *mut libc::timespec as usize,
                )
            };
            if syscall_result(ret).is_err() {
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
    if !force_native_threading_enabled()
        && thread != native_pthread_self()
        && !is_managed_thread_handle(thread)
        && let Some(host_gettid) = crate::host_resolve::host_pthread_gettid_np_raw()
    {
        return unsafe { host_gettid(thread) };
    }
    resolve_thread_tid(thread).unwrap_or(-1) as libc::pid_t
}

/// GNU `pthread_attr_getsigmask_np` — get signal mask from thread attributes.
/// Native implementation using extended attr registry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getsigmask_np(
    attr: *const libc::pthread_attr_t,
    sigmask: *mut libc::sigset_t,
) -> c_int {
    if managed_attr_data_ptr_const(attr).is_none() || sigmask.is_null() {
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
    let Some(data) = managed_attr_data_ptr(attr) else {
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
        Ok(d) => d.clone(),
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
        if defaults.extended.affinity.is_some() {
            (*data).flags |= 1;
        }
        if defaults.extended.sigmask.is_some() {
            (*data).flags |= 2;
        }
    }
    let key = attr as usize;
    let mut reg = match EXTENDED_ATTR_REGISTRY.lock() {
        Ok(r) => r,
        Err(_) => return libc::EINVAL,
    };
    if defaults.extended.affinity.is_some() || defaults.extended.sigmask.is_some() {
        reg.insert(key, defaults.extended.clone());
    } else {
        reg.remove(&key);
    }
    0
}

/// GNU `pthread_setattr_default_np` — set default thread attributes.
/// Native implementation using global default attr state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setattr_default_np(attr: *const libc::pthread_attr_t) -> c_int {
    let Some(data) = managed_attr_data_ptr_const(attr) else {
        return libc::EINVAL;
    };
    let key = attr as usize;
    let extended = {
        let reg = match EXTENDED_ATTR_REGISTRY.lock() {
            Ok(r) => r,
            Err(_) => return libc::EINVAL,
        };
        reg.get(&key).cloned().unwrap_or(ExtendedAttrData {
            affinity: None,
            sigmask: None,
        })
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
    defaults.extended = extended;
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

/// Probe helper for in-process host pthread resolution debugging.
///
/// Kind:
/// 1 = RTLD_NEXT/host nocache pthread_create
/// 2 = libc-handle pthread_create
/// 3 = direct loaded-libc ELF pthread_create
/// 4 = RTLD_NEXT/host nocache pthread_self
/// 5 = libc-handle pthread_self
/// 6 = direct loaded-libc ELF pthread_self
/// 7 = cached host pthread_create fn
/// 8 = direct loaded-libc ELF pthread_detach
/// 9 = cached host pthread_detach fn
/// 10 = direct loaded-libc ELF pthread_join
/// 11 = cached host pthread_join fn
/// 12 = direct loaded-libc ELF pthread_equal
/// 13 = cached host pthread_equal fn
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __frankenlibc_host_pthread_probe(kind: c_int) -> usize {
    match kind {
        1 => unsafe { resolve_host_symbol_nocache(b"pthread_create\0") as usize },
        2 => unsafe { resolve_host_symbol_via_libc_handle(b"pthread_create\0") as usize },
        3 => resolve_loaded_libc_symbol_direct("pthread_create").unwrap_or(0),
        4 => unsafe { resolve_host_symbol_nocache(b"pthread_self\0") as usize },
        5 => unsafe { resolve_host_symbol_via_libc_handle(b"pthread_self\0") as usize },
        6 => resolve_loaded_libc_symbol_direct("pthread_self").unwrap_or(0),
        7 => unsafe {
            host_pthread_create_fn()
                .map(|func| func as usize)
                .unwrap_or(0)
        },
        8 => resolve_loaded_libc_symbol_direct("pthread_detach").unwrap_or(0),
        9 => unsafe {
            host_pthread_detach_fn()
                .map(|func| func as usize)
                .unwrap_or(0)
        },
        10 => resolve_loaded_libc_symbol_direct("pthread_join").unwrap_or(0),
        11 => unsafe {
            host_pthread_join_fn()
                .map(|func| func as usize)
                .unwrap_or(0)
        },
        12 => resolve_loaded_libc_symbol_direct("pthread_equal").unwrap_or(0),
        13 => unsafe {
            host_pthread_equal_fn()
                .map(|func| func as usize)
                .unwrap_or(0)
        },
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    #[test]
    fn direct_libc_resolution_finds_host_pthread_symbols() {
        let create = resolve_loaded_libc_symbol_direct("pthread_create");
        let join = resolve_loaded_libc_symbol_direct("pthread_join");
        let self_fn = resolve_loaded_libc_symbol_direct("pthread_self");
        assert!(create.is_some(), "pthread_create not found in loaded libc");
        assert!(join.is_some(), "pthread_join not found in loaded libc");
        assert!(self_fn.is_some(), "pthread_self not found in loaded libc");
    }

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
