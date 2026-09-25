//! Native DSO thread-local destructors and loader lifetime pins.
//!
//! Only native relocation scopes bind to this registration function. The host
//! must never receive a native __dso_handle, nor may we register host callbacks
//! in this queue. The Rust thread-exit hook merely schedules our owned drain.

use std::cell::{Cell, RefCell};
use std::ffi::{c_int, c_void};
use std::sync::OnceLock;

use super::{NativeDso, OPERATIONS, lifecycle, registry};
use super::tls::Block;

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

struct Cleanup;
std::thread_local! {
    // A trivial key stays accessible while Cleanup is being destroyed. Putting
    // the state directly in a dropping LocalKey would reject TLS access from
    // within a C++ destructor, before the destructor has actually returned.
    static STATE: Cell<*mut ThreadState> = const { Cell::new(std::ptr::null_mut()) };
    static CLEANUP: Cleanup = const { Cleanup };
    static PROCESS_EXIT: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn with_state<T>(callback: impl FnOnce(&ThreadState) -> Option<T>) -> Option<T> {
    STATE.try_with(|slot| {
        let mut state = slot.get();
        if state.is_null() {
            // Ordinary worker teardown must not resurrect a dead cleanup key.
            // During process exit, late FINI calls may first touch a TLS block;
            // that state is instead retained until the kernel reclaims it.
            if !PROCESS_EXIT.with(Cell::get) { CLEANUP.try_with(|_| ()).ok()?; }
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
    }).ok().flatten()
}

/// Observe TLS without allocating state or registering a reclamation hook.
/// Inspection must not turn an untouched module into allocated thread storage.
pub(super) fn with_existing_state<T>(callback: impl FnOnce(&ThreadState) -> Option<T>) -> Option<T> {
    STATE.try_with(|slot| {
        let state = slot.get();
        if state.is_null() { return None; }
        // SAFETY: this thread exclusively owns the state, and the synchronous
        // observer neither reclaims it nor invokes foreign callbacks.
        callback(unsafe { &*state })
    }).ok().flatten()
}

fn drain_current() {
    let _ = STATE.try_with(|slot| {
        let state = slot.get();
        if state.is_null() { return; }
        loop {
            // SAFETY: this thread owns state through the entire drain.
            // Remove before invoking, with no borrow held across user code.
            let next = unsafe { &*state }.destructors.borrow_mut().pop();
            let Some(entry) = next else { break; };
            unsafe { (entry.destructor)(entry.argument) };
            release_pins(&entry.owners);
        }
    });
}

pub(super) fn prepare_process_exit() {
    PROCESS_EXIT.with(|flag| flag.set(true));
    drain_current();
}

type SetSpecific = unsafe extern "C" fn(libc::pthread_key_t, *const c_void) -> c_int;
struct Reclaimer { key: libc::pthread_key_t, set: SetSpecific }
static RECLAIMER: OnceLock<Option<Reclaimer>> = OnceLock::new();

fn attach_reclaimer(state: *mut ThreadState) -> bool {
    let reclaimer = RECLAIMER.get_or_init(|| {
        type Create = unsafe extern "C" fn(
            *mut libc::pthread_key_t, Option<unsafe extern "C" fn(*mut c_void)>,
        ) -> c_int;
        let create = crate::host_resolve::resolve_host_symbol_raw("pthread_key_create")?;
        let set = crate::host_resolve::resolve_host_symbol_raw("pthread_setspecific")?;
        // SAFETY: the private key belongs to host threads. This schedules only
        // reclamation of our heap state; native module IDs never enter its DTV.
        let create: Create = unsafe { core::mem::transmute(create) };
        let set: SetSpecific = unsafe { std::mem::transmute(set) };
        let mut key = 0;
        if unsafe { create(&mut key, Some(reclaim)) } != 0 { return None; }
        Some(Reclaimer { key, set })
    });
    reclaimer.as_ref().is_some_and(|reclaimer| {
        unsafe { (reclaimer.set)(reclaimer.key, state.cast()) == 0 }
    })
}

unsafe extern "C" fn reclaim(pointer: *mut c_void) {
    if pointer.is_null() { return; }
    // pthread-key destructors run on ordinary thread termination, but not on
    // normal process exit. Deferring allocation reclamation to this stage
    // keeps TLS valid for process finalizers even when a worker calls exit.
    // Drain defensively: correctness does not depend on Rust's TLS strategy.
    drain_current();
    let _ = STATE.try_with(|slot| slot.set(std::ptr::null_mut()));
    // SAFETY: one key value owns the one Box registered by attach_reclaimer.
    unsafe { drop(Box::from_raw(pointer.cast::<ThreadState>())) };
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        // Run native C++ TLS callbacks at Rust/C++ thread-exit time, retaining
        // their storage until pthread-key cleanup or process reclamation.
        drain_current();
    }
}

fn contains_address(dso: &NativeDso, address: usize) -> bool {
    let Some(offset) = (address as u64).checked_sub(dso.object.base) else { return false; };
    dso.object.program_headers.iter().any(|segment| {
        segment.is_load() && segment.p_vaddr <= offset
            && segment.p_vaddr.checked_add(segment.p_memsz).is_some_and(|end| offset < end)
    })
}

fn register(destructor: Destructor, argument: *mut c_void, dso_handle: *mut c_void) -> Option<()> {
    let _operation = OPERATIONS.lock();
    with_state(|state| {
        let mut entries = state.destructors.try_borrow_mut().ok()?;
        entries.try_reserve(1).ok()?;
        let mut dsos = registry().lock().ok()?;
        let owner = dsos.iter().find(|dso| !dso.retiring && contains_address(dso, dso_handle as usize))?.id;
        let provider = dsos.iter().find(|dso| {
            !dso.retiring && lifecycle::executable_address(dso, destructor as *const () as usize)
        })?.id;
        let mut owners = vec![owner];
        if provider != owner { owners.push(provider); }
        // Check all counts before changing any resident state. Once pinned,
        // the reserved queue slot cannot fail and owns exactly these pins.
        for id in &owners {
            dsos.iter().find(|dso| dso.id == *id)?.thread_exit_pins.checked_add(1)?;
        }
        for dso in dsos.iter_mut().filter(|dso| owners.contains(&dso.id)) {
            dso.thread_exit_pins += 1;
        }
        entries.push(Entry { destructor, argument, owners });
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
    destructor: Option<Destructor>, argument: *mut c_void, dso_handle: *mut c_void,
) -> c_int {
    let Some(destructor) = destructor else { return -1; };
    if register(destructor, argument, dso_handle).is_some() { 0 } else { -1 }
}

pub(super) fn resolver_address(version: Option<&str>) -> Option<u64> {
    if version.is_some_and(|version| version != "GLIBC_2.18") { return None; }
    Some(register_impl as *const () as usize as u64)
}
