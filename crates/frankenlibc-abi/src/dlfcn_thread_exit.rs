//! Native DSO thread-local destructors and loader lifetime pins.
//!
//! Only native relocation scopes bind to this registration function. The host
//! must never receive a native __dso_handle, nor may we register host callbacks
//! in this queue. The Rust thread-exit hook merely schedules our owned drain.

#[cfg(not(feature = "owned-tls-cache"))]
use std::cell::Cell;
use std::cell::RefCell;
use std::ffi::{c_int, c_void};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use super::tls::Block;
use super::{NativeDso, OPERATIONS, lifecycle, registry};

type Destructor = unsafe extern "C" fn(*mut c_void);

struct Entry {
    destructor: Destructor,
    argument: *mut c_void,
    // Pin both the registering DSO and the callback provider. They can differ
    // (e.g. an inline C++ destructor preempted by another native library).
    owners: Vec<usize>,
}

#[derive(Default)]
pub(super) struct ThreadState {
    pub(super) blocks: RefCell<Vec<Block>>,
    destructors: RefCell<Vec<Entry>>,
}

#[cfg(not(feature = "owned-tls-cache"))]
struct Cleanup;
#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    // A trivial key stays accessible while Cleanup is being destroyed. Putting
    // the state directly in a dropping LocalKey would reject TLS access from
    // within a C++ destructor, before the destructor has actually returned.
    static STATE: Cell<*mut ThreadState> = const { Cell::new(std::ptr::null_mut()) };
    static CLEANUP: Cleanup = const { Cleanup };
    static PROCESS_EXIT: Cell<bool> = const { Cell::new(false) };
}

static NATIVE_THREAD_STATES: parking_lot::Mutex<Vec<(i32, usize)>> =
    parking_lot::Mutex::new(Vec::new());
static NATIVE_PROCESS_EXIT: AtomicBool = AtomicBool::new(false);

#[cfg(not(test))]
pub(crate) struct ThreadExitForkGuard {
    parent_tid: i32,
    _guard: Option<parking_lot::MutexGuard<'static, Vec<(i32, usize)>>>,
}

#[cfg(not(test))]
pub(crate) fn lock_thread_exit_for_fork() -> ThreadExitForkGuard {
    ThreadExitForkGuard {
        parent_tid: current_exit_tid(),
        _guard: Some(NATIVE_THREAD_STATES.lock()),
    }
}

#[cfg(not(test))]
impl ThreadExitForkGuard {
    pub(crate) fn adopt_and_unlock_in_fork_child(&mut self) {
        if let Some(mut states) = self._guard.take() {
            // Dead sibling threads do not exist in the forked child; re-key the
            // surviving thread's entry from `parent_tid` to `child_tid` and drop
            // all dead sibling rows so a recycled child TID never aliases them.
            let child_tid = current_exit_tid();
            let survivor = states
                .iter()
                .find_map(|&(tid, ptr)| (tid == self.parent_tid).then_some(ptr));
            states.clear();
            if let Some(ptr) = survivor {
                states.push((child_tid, ptr));
            }
        }
    }
}

#[inline]
fn use_tid_keyed_thread_exit() -> bool {
    #[cfg(any(feature = "standalone", feature = "owned-tls-cache"))]
    {
        true
    }
    #[cfg(not(any(feature = "standalone", feature = "owned-tls-cache")))]
    {
        #[cfg(not(test))]
        {
            crate::malloc_abi::native_thread_backend_active()
                || frankenlibc_core::pthread::thread::current_thread_handle().is_some()
        }
        #[cfg(test)]
        {
            false
        }
    }
}

#[inline]
fn current_exit_tid() -> i32 {
    frankenlibc_core::syscall::raw_gettid_nocancel().max(1)
}

fn lookup_native_state(tid: i32) -> *mut ThreadState {
    let guard = NATIVE_THREAD_STATES.lock();
    guard
        .iter()
        .find_map(|&(entry_tid, ptr)| (entry_tid == tid).then_some(ptr as *mut ThreadState))
        .unwrap_or(std::ptr::null_mut())
}

fn insert_native_state(tid: i32, ptr: *mut ThreadState) {
    let mut guard = NATIVE_THREAD_STATES.lock();
    if let Some((_, slot)) = guard.iter_mut().find(|(entry_tid, _)| *entry_tid == tid) {
        *slot = ptr as usize;
    } else {
        guard.push((tid, ptr as usize));
    }
}

fn remove_native_state_ptr(ptr: *mut ThreadState) {
    let mut guard = NATIVE_THREAD_STATES.lock();
    guard.retain(|&(_, stored)| stored != ptr as usize);
}

#[cfg(not(test))]
pub(crate) fn migrate_creator_thread_exit_for_native_threads() {
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        let existing = STATE
            .try_with(|slot| slot.replace(std::ptr::null_mut()))
            .unwrap_or(std::ptr::null_mut());
        if !existing.is_null() {
            insert_native_state(current_exit_tid(), existing);
        }
        if PROCESS_EXIT.try_with(Cell::get).unwrap_or(false) {
            NATIVE_PROCESS_EXIT.store(true, Ordering::Release);
        }
    }
}

pub(super) fn with_state<T>(callback: impl FnOnce(&ThreadState) -> Option<T>) -> Option<T> {
    if use_tid_keyed_thread_exit() {
        let tid = current_exit_tid();
        let mut state = lookup_native_state(tid);
        if state.is_null() {
            let allocation = Box::new(ThreadState::default());
            state = Box::into_raw(allocation);
            if !NATIVE_PROCESS_EXIT.load(Ordering::Acquire) && !attach_native_reclaimer(state) {
                // SAFETY: registration failed before the pointer was exposed.
                unsafe { drop(Box::from_raw(state)) };
                return None;
            }
            insert_native_state(tid, state);
        }
        // SAFETY: each TID exclusively owns its heap-pinned `ThreadState`.
        return callback(unsafe { &*state });
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        STATE
            .try_with(|slot| {
                let mut state = slot.get();
                if state.is_null() {
                    // Ordinary worker teardown must not resurrect a dead cleanup key.
                    // During process exit, late FINI calls may first touch a TLS block;
                    // that state is instead retained until the kernel reclaims it.
                    if !PROCESS_EXIT.with(Cell::get) {
                        CLEANUP.try_with(|_| ()).ok()?;
                    }
                    let allocation = Box::new(ThreadState::default());
                    state = Box::into_raw(allocation);
                    if !PROCESS_EXIT.with(Cell::get) && !attach_reclaimer(state) {
                        // SAFETY: registration failed before the pointer was exposed.
                        unsafe { drop(Box::from_raw(state)) };
                        return None;
                    }
                    slot.set(state);
                }
                // SAFETY: only this thread accesses its heap-pinned state. Cleanup
                // leaves it alive until every callback (including new ones) returns.
                callback(unsafe { &*state })
            })
            .ok()
            .flatten()
    }
    #[cfg(feature = "owned-tls-cache")]
    {
        let _ = callback;
        None
    }
}

/// Observe TLS without allocating state or registering a reclamation hook.
/// Inspection must not turn an untouched module into allocated thread storage.
pub(super) fn with_existing_state<T>(
    callback: impl FnOnce(&ThreadState) -> Option<T>,
) -> Option<T> {
    if use_tid_keyed_thread_exit() {
        let state = lookup_native_state(current_exit_tid());
        if state.is_null() {
            return None;
        }
        // SAFETY: this TID exclusively owns the state, and the synchronous
        // observer neither reclaims it nor invokes foreign callbacks.
        return callback(unsafe { &*state });
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        STATE
            .try_with(|slot| {
                let state = slot.get();
                if state.is_null() {
                    return None;
                }
                // SAFETY: this thread exclusively owns the state, and the synchronous
                // observer neither reclaims it nor invokes foreign callbacks.
                callback(unsafe { &*state })
            })
            .ok()
            .flatten()
    }
    #[cfg(feature = "owned-tls-cache")]
    {
        let _ = callback;
        None
    }
}

fn drain_state(state: *mut ThreadState) {
    if state.is_null() {
        return;
    }
    loop {
        // SAFETY: this thread owns `state` through the entire drain.
        // Remove before invoking, with no borrow held across user code.
        let next = unsafe { &*state }.destructors.borrow_mut().pop();
        let Some(entry) = next else {
            break;
        };
        unsafe { (entry.destructor)(entry.argument) };
        release_pins(&entry.owners);
    }
}

fn drain_current() {
    if use_tid_keyed_thread_exit() {
        drain_state(lookup_native_state(current_exit_tid()));
        return;
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        let _ = STATE.try_with(|slot| drain_state(slot.get()));
    }
}

pub(super) fn prepare_process_exit() {
    NATIVE_PROCESS_EXIT.store(true, Ordering::Release);
    #[cfg(not(feature = "owned-tls-cache"))]
    if !use_tid_keyed_thread_exit() {
        let _ = PROCESS_EXIT.try_with(|flag| flag.set(true));
    }
    drain_current();
}

type SetSpecific = unsafe extern "C" fn(libc::pthread_key_t, *const c_void) -> c_int;
struct Reclaimer {
    key: libc::pthread_key_t,
    set: SetSpecific,
}
static NATIVE_RECLAIMER: OnceLock<Option<Reclaimer>> = OnceLock::new();
#[cfg(not(any(feature = "standalone", feature = "owned-tls-cache")))]
static HOST_RECLAIMER: OnceLock<Option<Reclaimer>> = OnceLock::new();

fn attach_native_reclaimer(state: *mut ThreadState) -> bool {
    let reclaimer = NATIVE_RECLAIMER.get_or_init(|| {
        let mut key = 0;
        if unsafe { crate::pthread_abi::pthread_key_create(&mut key, Some(reclaim)) } != 0 {
            return None;
        }
        Some(Reclaimer {
            key,
            set: crate::pthread_abi::pthread_setspecific,
        })
    });
    reclaimer
        .as_ref()
        .is_some_and(|reclaimer| unsafe { (reclaimer.set)(reclaimer.key, state.cast()) == 0 })
}

#[cfg(not(any(feature = "standalone", feature = "owned-tls-cache")))]
fn attach_reclaimer(state: *mut ThreadState) -> bool {
    if frankenlibc_core::pthread::thread::current_thread_handle().is_some() {
        return attach_native_reclaimer(state);
    }
    let reclaimer = HOST_RECLAIMER.get_or_init(|| {
        type Create = unsafe extern "C" fn(
            *mut libc::pthread_key_t,
            Option<unsafe extern "C" fn(*mut c_void)>,
        ) -> c_int;
        let create = crate::host_resolve::resolve_host_symbol_raw("pthread_key_create")?;
        let set = crate::host_resolve::resolve_host_symbol_raw("pthread_setspecific")?;
        // SAFETY: the private key belongs to host threads. This schedules only
        // reclamation of our heap state; native module IDs never enter its DTV.
        let create: Create = unsafe { core::mem::transmute(create) };
        let set: SetSpecific = unsafe { std::mem::transmute(set) };
        let mut key = 0;
        if unsafe { create(&mut key, Some(reclaim)) } != 0 {
            return None;
        }
        Some(Reclaimer { key, set })
    });
    reclaimer
        .as_ref()
        .is_some_and(|reclaimer| unsafe { (reclaimer.set)(reclaimer.key, state.cast()) == 0 })
}

#[cfg(all(feature = "standalone", not(feature = "owned-tls-cache")))]
fn attach_reclaimer(state: *mut ThreadState) -> bool {
    attach_native_reclaimer(state)
}

unsafe extern "C" fn reclaim(pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
    let state = pointer.cast::<ThreadState>();
    // pthread-key destructors run on ordinary thread termination, but not on
    // normal process exit. Drain `state` directly (safe for both TID-keyed and
    // host-TLS paths) before clearing the lookup entry and freeing the Box.
    drain_state(state);
    remove_native_state_ptr(state);
    #[cfg(not(feature = "owned-tls-cache"))]
    if !use_tid_keyed_thread_exit() {
        let _ = STATE.try_with(|slot| {
            if slot.get() == state {
                slot.set(std::ptr::null_mut());
            }
        });
    }
    // SAFETY: one key value owns the one Box registered by attach_*_reclaimer.
    unsafe { drop(Box::from_raw(state)) };
}

#[cfg(not(feature = "owned-tls-cache"))]
impl Drop for Cleanup {
    fn drop(&mut self) {
        // Run native C++ TLS callbacks at Rust/C++ thread-exit time, retaining
        // their storage until pthread-key cleanup or process reclamation.
        drain_current();
    }
}

fn contains_address(dso: &NativeDso, address: usize) -> bool {
    let Some(offset) = (address as u64).checked_sub(dso.object.base) else {
        return false;
    };
    dso.object.program_headers.iter().any(|segment| {
        segment.is_load()
            && segment.p_vaddr <= offset
            && segment
                .p_vaddr
                .checked_add(segment.p_memsz)
                .is_some_and(|end| offset < end)
    })
}

fn register(destructor: Destructor, argument: *mut c_void, dso_handle: *mut c_void) -> Option<()> {
    let _operation = OPERATIONS.lock();
    with_state(|state| {
        let mut entries = state.destructors.try_borrow_mut().ok()?;
        entries.try_reserve(1).ok()?;
        let mut dsos = registry().lock().ok()?;
        let owner = dsos
            .iter()
            .find(|dso| !dso.retiring && contains_address(dso, dso_handle as usize))?
            .id;
        let provider = dsos
            .iter()
            .find(|dso| {
                !dso.retiring
                    && lifecycle::executable_address(dso, destructor as *const () as usize)
            })?
            .id;
        let mut owners = vec![owner];
        if provider != owner {
            owners.push(provider);
        }
        // Check all counts before changing any resident state. Once pinned,
        // the reserved queue slot cannot fail and owns exactly these pins.
        for id in &owners {
            dsos.iter()
                .find(|dso| dso.id == *id)?
                .thread_exit_pins
                .checked_add(1)?;
        }
        for dso in dsos.iter_mut().filter(|dso| owners.contains(&dso.id)) {
            dso.thread_exit_pins += 1;
        }
        entries.push(Entry {
            destructor,
            argument,
            owners,
        });
        Some(())
    })
}

fn release_pins(owners: &[usize]) {
    let _operation = OPERATIONS.lock();
    if let Ok(mut dsos) = registry().lock() {
        for dso in dsos.iter_mut().filter(|dso| owners.contains(&dso.id)) {
            // A pin is released only by the entry that acquired it, and pinned
            // DSOs cannot have been collected in the meantime.
            dso.thread_exit_pins -= 1;
        }
    }
    // Match host lifetime behavior: releasing the final TLS pin does not run
    // dlclose finalizers recursively on the exiting thread. The next loader
    // collection can retire an otherwise unreferenced library.
}

unsafe extern "C" fn register_impl(
    destructor: Option<Destructor>,
    argument: *mut c_void,
    dso_handle: *mut c_void,
) -> c_int {
    let Some(destructor) = destructor else {
        return -1;
    };
    if register(destructor, argument, dso_handle).is_some() {
        0
    } else {
        -1
    }
}

pub(super) fn resolver_address(version: Option<&str>) -> Option<u64> {
    if version.is_some_and(|version| version != "GLIBC_2.18") {
        return None;
    }
    Some(register_impl as *const () as usize as u64)
}
