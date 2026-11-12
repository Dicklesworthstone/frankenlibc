//! Native DSO thread-local destructors and loader lifetime pins.
//!
//! Only native relocation scopes bind to this registration function. The host
//! must never receive a native __dso_handle, nor may we register host callbacks
//! in this queue. Hosted threads use Rust/host exit hooks; native clone threads
//! keep their state and exit hooks in their native ThreadHandle instead of
//! their inherited compiler TLS.

use std::alloc::Layout;
use std::cell::{Cell, RefCell};
use std::ffi::{c_int, c_void};
use std::mem::ManuallyDrop;
use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::{Arc, OnceLock};
use std::sync::atomic::{AtomicPtr, Ordering};

use frankenlibc_core::pthread::thread::{RuntimeTlsState, ThreadHandle, current_thread_handle};
use frankenlibc_core::syscall;

use super::tls::{Block, Module};
use super::{NativeDso, OPERATIONS, lifecycle, registry};

type Destructor = unsafe extern "C" fn(*mut c_void);

struct Entry {
    destructor: Destructor,
    argument: *mut c_void,
    // Pin both the registering DSO and the callback provider. They can differ
    // (e.g. an inline C++ destructor preempted by another native library).
    owners: [usize; 2],
    owner_count: usize,
}

/// Anonymous storage for native TLS. Raw syscalls neither allocate from a
/// host arena nor consult the creator's inherited errno/compiler TLS.
pub(super) struct MappedAllocation {
    base: NonNull<u8>,
    data: NonNull<u8>,
    len: usize,
}

impl MappedAllocation {
    pub(super) fn new(layout: Layout) -> Option<Self> {
        let len = layout.size().max(1).checked_add(layout.align() - 1)?;
        // SAFETY: anonymous private read/write mapping, checked nonzero size.
        let base = NonNull::new(unsafe {
            syscall::sys_mmap(std::ptr::null_mut(), len, 3, 0x22, -1, 0).ok()?
        })?;
        let padding = base.as_ptr().align_offset(layout.align());
        if padding > layout.align() - 1 {
            // SAFETY: this unpublished mapping is exclusively owned.
            let _ = unsafe { syscall::sys_munmap(base.as_ptr(), len) };
            return None;
        }
        // SAFETY: padding and the complete layout fit within the mapping.
        let data = unsafe { NonNull::new_unchecked(base.as_ptr().add(padding)) };
        Some(Self { base, data, len })
    }

    pub(super) fn as_ptr(&self) -> *mut u8 {
        self.data.as_ptr()
    }
}

impl Drop for MappedAllocation {
    fn drop(&mut self) {
        // SAFETY: the owner dropped all values before releasing this map.
        let _ = unsafe { syscall::sys_munmap(self.base.as_ptr(), self.len) };
    }
}

/// Growable native-thread storage with no host allocator dependency.
/// Copying the initialized prefix transfers ownership to a new mapping;
/// unmapping the old allocation must not drop those moved values again.
struct MappedVec<T> {
    allocation: Option<MappedAllocation>,
    len: usize,
    capacity: usize,
    element: std::marker::PhantomData<T>,
}

impl<T> MappedVec<T> {
    fn new() -> Self {
        Self { allocation: None, len: 0, capacity: 0, element: std::marker::PhantomData }
    }

    fn as_ptr(&self) -> *mut T {
        self.allocation.as_ref().map_or_else(
            || NonNull::<T>::dangling().as_ptr(),
            |allocation| allocation.as_ptr().cast(),
        )
    }

    fn try_reserve(&mut self, additional: usize) -> Option<()> {
        let needed = self.len.checked_add(additional)?;
        if needed <= self.capacity {
            return Some(());
        }
        let capacity = self.capacity.checked_mul(2).unwrap_or(needed).max(needed).max(4);
        let allocation = MappedAllocation::new(Layout::array::<T>(capacity).ok()?)?;
        // SAFETY: aligned, nonoverlapping allocations; exactly len initialized
        // elements move to the new map. The old map contains no owned values.
        unsafe {
            std::ptr::copy_nonoverlapping(self.as_ptr(), allocation.as_ptr().cast(), self.len)
        };
        self.allocation = Some(allocation);
        self.capacity = capacity;
        Some(())
    }

    fn push_reserved(&mut self, value: T) {
        assert!(self.len < self.capacity);
        // SAFETY: callers reserve first; this slot is not yet initialized.
        unsafe { self.as_ptr().add(self.len).write(value) };
        self.len += 1;
    }

    fn pop(&mut self) -> Option<T> {
        self.len = self.len.checked_sub(1)?;
        // SAFETY: withdrawing the final initialized element transfers it to
        // the caller and excludes it from future slice/drop operations.
        Some(unsafe { self.as_ptr().add(self.len).read() })
    }

    fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        let mut index = 0;
        while index < self.len {
            // SAFETY: index is within the initialized prefix.
            if keep(unsafe { &*self.as_ptr().add(index) }) {
                index += 1;
                continue;
            }
            // SAFETY: remove one value and move the suffix left. The reduced
            // len excludes the duplicate bytes beyond the initialized prefix.
            let removed = unsafe { self.as_ptr().add(index).read() };
            unsafe {
                std::ptr::copy(self.as_ptr().add(index + 1), self.as_ptr().add(index), self.len - index - 1)
            };
            self.len -= 1;
            drop(removed);
        }
    }
}

impl<T> Deref for MappedVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        // SAFETY: the aligned pointer covers len live elements, or is a
        // correctly aligned dangling pointer for the empty slice.
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.len) }
    }
}

impl<T> Drop for MappedVec<T> {
    fn drop(&mut self) {
        // SAFETY: drop the initialized prefix once, before allocation's Drop
        // unmaps the memory containing the elements.
        unsafe {
            std::ptr::drop_in_place(std::ptr::slice_from_raw_parts_mut(self.as_ptr(), self.len))
        };
    }
}

pub(super) struct ThreadStorage<T> {
    hosted: Vec<T>,
    native: Option<MappedVec<T>>,
}

impl<T> Default for ThreadStorage<T> {
    fn default() -> Self {
        Self { hosted: Vec::new(), native: None }
    }
}

impl<T> ThreadStorage<T> {
    fn native() -> Self {
        Self { hosted: Vec::new(), native: Some(MappedVec::new()) }
    }

    pub(super) fn try_reserve(&mut self, additional: usize) -> Option<()> {
        match &mut self.native {
            Some(native) => native.try_reserve(additional),
            None => self.hosted.try_reserve(additional).ok(),
        }
    }

    pub(super) fn push_reserved(&mut self, value: T) {
        match &mut self.native {
            Some(native) => native.push_reserved(value),
            None => self.hosted.push(value),
        }
    }

    fn pop(&mut self) -> Option<T> {
        match &mut self.native {
            Some(native) => native.pop(),
            None => self.hosted.pop(),
        }
    }

    pub(super) fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        match &mut self.native {
            Some(native) => native.retain(keep),
            None => self.hosted.retain(keep),
        }
    }
}

impl<T> Deref for ThreadStorage<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        self.native.as_deref().unwrap_or(&self.hosted)
    }
}

pub(super) type TemporaryTlsModules = Vec<(usize, Arc<Module>)>;

#[derive(Default)]
pub(super) struct ThreadState {
    pub(super) blocks: RefCell<ThreadStorage<Block>>,
    destructors: RefCell<ThreadStorage<Entry>>,
    pub(super) native: bool,
    // Borrowed only while an IFUNC Execution guard retains its Context.
    // A thin atomic pointer keeps signal reentry from observing torn metadata.
    pub(super) ifunc_modules: AtomicPtr<TemporaryTlsModules>,
}

#[repr(C)]
struct NativeThreadState {
    header: RuntimeTlsState,
    state: ThreadState,
    allocation: ManuallyDrop<MappedAllocation>,
}

fn native_state(handle: *mut ThreadHandle, initialize: bool) -> Option<*mut ThreadState> {
    // SAFETY: current_thread_handle gives this caller its live native handle.
    let slot = unsafe { &(*handle).runtime_tls };
    let mut state = slot.load(Ordering::Acquire).cast::<NativeThreadState>();
    if state.is_null() && initialize {
        let allocation = MappedAllocation::new(Layout::new::<NativeThreadState>())?;
        let initialized = allocation.as_ptr().cast::<NativeThreadState>();
        // SAFETY: the aligned mapping covers the complete state. Nothing can
        // observe the header/payload until the release publication below.
        unsafe {
            initialized.write(NativeThreadState {
                header: RuntimeTlsState { drain: drain_native, reclaim: reclaim_native },
                state: ThreadState {
                    blocks: RefCell::new(ThreadStorage::native()),
                    destructors: RefCell::new(ThreadStorage::native()),
                    native: true,
                    ifunc_modules: AtomicPtr::new(std::ptr::null_mut()),
                },
                allocation: ManuallyDrop::new(allocation),
            })
        };
        state = match slot.compare_exchange(
            std::ptr::null_mut(), initialized.cast(), Ordering::AcqRel, Ordering::Acquire,
        ) {
            Ok(_) => initialized,
            Err(existing) => {
                // SAFETY: a signal handler won initialization. The losing,
                // unpublished state contains no entries and is exclusively ours.
                unsafe { reclaim_native(initialized.cast()) };
                existing.cast()
            }
        };
    }
    if state.is_null() {
        None
    } else {
        // SAFETY: the owner retains this published allocation until core exit.
        Some(unsafe { std::ptr::addr_of_mut!((*state).state) })
    }
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
    if let Some(handle) = current_thread_handle() {
        let state = native_state(handle, true)?;
        // SAFETY: this native owner retains its independent state through all
        // application destructors. OOM never falls back to inherited host TLS.
        return callback(unsafe { &*state });
    }
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

/// Observe TLS without allocating state or registering a reclamation hook.
/// Inspection must not turn an untouched module into allocated thread storage.
pub(super) fn with_existing_state<T>(
    callback: impl FnOnce(&ThreadState) -> Option<T>,
) -> Option<T> {
    if let Some(handle) = current_thread_handle() {
        let state = native_state(handle, false)?;
        // SAFETY: this is the current native owner's existing live payload.
        return callback(unsafe { &*state });
    }
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

fn drain_current() {
    let _ = with_existing_state(|state| {
        drain(state, false);
        Some(())
    });
}

fn drain(state: &ThreadState, final_drain: bool) {
    // A callback may initiate thread cancellation after an ordinary return.
    // Release its code/data pins when unwinding abandons this drain too. Keep
    // this guard local: dropping a queued Entry elsewhere must not acquire
    // loader locks or release pins whose registration has not committed.
    struct CallbackPins<'a>(&'a [usize]);
    impl Drop for CallbackPins<'_> {
        fn drop(&mut self) {
            release_pins(self.0);
        }
    }

    loop {
        if final_drain {
            let blocked = u64::MAX;
            // SAFETY: Linux x86-64/AArch64 kernel sigsets are one u64. Repeat
            // after every callback: application code may have unblocked them.
            if unsafe {
                syscall::sys_rt_sigprocmask(
                    2, std::ptr::from_ref(&blocked).cast(), std::ptr::null_mut(),
                    std::mem::size_of::<u64>(),
                )
            }.is_err() {
                syscall::sys_exit_group(127);
            }
        }
        // Remove before invoking, with no borrow or loader lock held across
        // application code. A callback may register another entry to drain.
        let next = state.destructors.borrow_mut().pop();
        let Some(entry) = next else {
            break;
        };
        let _pins = CallbackPins(&entry.owners[..entry.owner_count]);
        // SAFETY: registration validated and pinned the callback and owner.
        // C and C-unwind have the same machine ABI; a cancellation point in
        // this application callback must not cross a nounwind Rust call.
        let destructor: unsafe extern "C-unwind" fn(*mut c_void) =
            unsafe { core::mem::transmute(entry.destructor) };
        unsafe { destructor(entry.argument) };
    }
}

unsafe fn drain_native(pointer: *mut RuntimeTlsState, final_drain: bool) {
    // SAFETY: NativeThreadState embeds its header first. The native owner
    // retains its allocation, identity and TLS blocks throughout this drain.
    let state = unsafe { &(*pointer.cast::<NativeThreadState>()).state };
    drain(state, final_drain);
}

unsafe fn reclaim_native(pointer: *mut RuntimeTlsState) {
    let state = pointer.cast::<NativeThreadState>();
    // SAFETY: core withdrew the pointer with signals blocked after the final
    // drain, or initialization lost before publication. No callbacks remain.
    let allocation = unsafe { ManuallyDrop::take(&mut (*state).allocation) };
    unsafe { std::ptr::drop_in_place(state) };
    drop(allocation);
}

pub(super) fn prepare_process_exit() {
    if current_thread_handle().is_none() {
        PROCESS_EXIT.with(|flag| flag.set(true));
    }
    drain_current();
}

type SetSpecific = unsafe extern "C" fn(libc::pthread_key_t, *const c_void) -> c_int;
struct Reclaimer {
    key: libc::pthread_key_t,
    set: SetSpecific,
}
static RECLAIMER: OnceLock<Option<Reclaimer>> = OnceLock::new();

fn attach_reclaimer(state: *mut ThreadState) -> bool {
    let reclaimer = RECLAIMER.get_or_init(|| {
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

unsafe extern "C" fn reclaim(pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
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
        entries.try_reserve(1)?;
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
        let owners = [owner, provider];
        let owner_count = if provider == owner { 1 } else { 2 };
        // Check all counts before changing any resident state. Once pinned,
        // the reserved queue slot cannot fail and owns exactly these pins.
        for id in &owners[..owner_count] {
            dsos.iter()
                .find(|dso| dso.id == *id)?
                .thread_exit_pins
                .checked_add(1)?;
        }
        for dso in dsos.iter_mut().filter(|dso| owners[..owner_count].contains(&dso.id)) {
            dso.thread_exit_pins += 1;
        }
        entries.push_reserved(Entry {
            destructor,
            argument,
            owners,
            owner_count,
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
