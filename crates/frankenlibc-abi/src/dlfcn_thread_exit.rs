//! Native thread-local destructors and loader lifetime pins.
//!
//! Native relocation scopes and public registrations on managed native threads
//! share this queue. Native DSOs receive lifetime pins; public callbacks may
//! also belong to the executable or the explicitly pinned runtime. Other host
//! owners/providers are rejected. The host never receives a native __dso_handle.
//! Hosted threads retain their existing exit hooks; native clones keep their
//! state and exit hooks in ThreadHandle, outside inherited compiler TLS.

use std::alloc::Layout;
#[cfg(not(feature = "owned-tls-cache"))]
use std::cell::Cell;
use std::cell::RefCell;
use std::ffi::{c_int, c_void};
use std::mem::ManuallyDrop;
use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, OnceLock};

use frankenlibc_core::pthread::thread::{RuntimeTlsState, ThreadHandle, current_thread_handle};
use frankenlibc_core::syscall;

use super::tls::{Block, Module};
use super::{NativeDso, OPERATIONS, lifecycle, registry};

type Destructor = unsafe extern "C" fn(*mut c_void);

// A native clone must not enter the host loader through its creator's TCB.
// Prepare the only host images admitted by public native registrations before
// the first clone: the executable cannot unload, and a retained loader handle
// pins this runtime. Other host DSOs require an unsupported lifetime bridge.
#[derive(Clone, Copy)]
struct ProcessImageSegment {
    start: usize,
    end: usize,
    flags: u32,
}

#[derive(Clone, Copy)]
struct ProcessImage {
    base: usize,
    segments: [ProcessImageSegment; 16],
    len: usize,
}

impl ProcessImage {
    fn from_phdrs(base: usize, phdrs: &[libc::Elf64_Phdr]) -> Option<Self> {
        let mut image = Self {
            base,
            segments: [ProcessImageSegment {
                start: 0,
                end: 0,
                flags: 0,
            }; 16],
            len: 0,
        };
        for header in phdrs {
            if header.p_type != libc::PT_LOAD || header.p_memsz == 0 {
                continue;
            }
            if image.len == image.segments.len() {
                return None;
            }
            let start = base.checked_add(usize::try_from(header.p_vaddr).ok()?)?;
            let end = start.checked_add(usize::try_from(header.p_memsz).ok()?)?;
            image.segments[image.len] = ProcessImageSegment {
                start,
                end,
                flags: header.p_flags,
            };
            image.len += 1;
        }
        (image.len != 0).then_some(image)
    }

    fn contains(&self, address: usize, executable: bool) -> bool {
        self.segments[..self.len].iter().any(|segment| {
            segment.start <= address
                && address < segment.end
                && (!executable || segment.flags & libc::PF_X != 0)
        })
    }
}

struct ProcessTlsOwners {
    main: Option<ProcessImage>,
    runtime: Option<ProcessImage>,
    // Deliberately retained for the process lifetime: native thread entry,
    // teardown and queued runtime callbacks must all remain executable.
    _runtime_pin: usize,
}

static PROCESS_TLS_OWNERS: OnceLock<ProcessTlsOwners> = OnceLock::new();

fn executable_image() -> Option<ProcessImage> {
    // The startup auxv cache is seeded from the real kernel vector. This runs
    // on a hosted creator (or initial standalone thread), never on a clone.
    let phdr = unsafe { crate::stdlib_abi::getauxval(libc::AT_PHDR) } as usize;
    let count = unsafe { crate::stdlib_abi::getauxval(libc::AT_PHNUM) } as usize;
    let entry = unsafe { crate::stdlib_abi::getauxval(libc::AT_PHENT) } as usize;
    if phdr == 0
        || count == 0
        || count > 4096
        || entry != std::mem::size_of::<libc::Elf64_Phdr>()
        || !phdr.is_multiple_of(std::mem::align_of::<libc::Elf64_Phdr>())
    {
        return None;
    }
    // SAFETY: these bounded, aligned program headers come from kernel auxv;
    // the executable and its header table remain mapped for process lifetime.
    let headers = unsafe { std::slice::from_raw_parts(phdr as *const libc::Elf64_Phdr, count) };
    let table = headers
        .iter()
        .find(|header| header.p_type == libc::PT_PHDR)?;
    let base = phdr.checked_sub(usize::try_from(table.p_vaddr).ok()?)?;
    ProcessImage::from_phdrs(base, headers)
}

#[cfg(not(feature = "standalone"))]
fn pin_runtime_image() -> Option<(ProcessImage, usize)> {
    // A successful host dlopen/dlinfo may free an earlier host dlerror buffer.
    // pthread_create must preserve that public pending/returned pointer. If
    // one exists, leave the runtime unadmitted rather than invalidate it or
    // claim a lifetime pin that was never acquired; executable/native owners
    // remain supported through their independent lifetime proofs.
    if crate::dlfcn_abi::hosted_dlerror_pointer_outstanding() {
        return None;
    }
    struct Scan {
        address: usize,
        image: Option<ProcessImage>,
        name: [u8; 4096],
    }
    unsafe extern "C" fn collect(
        info: *mut libc::dl_phdr_info,
        size: usize,
        data: *mut c_void,
    ) -> c_int {
        if info.is_null()
            || data.is_null()
            || size
                < std::mem::offset_of!(libc::dl_phdr_info, dlpi_phnum)
                    + std::mem::size_of::<libc::Elf64_Half>()
        {
            return 0;
        }
        // SAFETY: the host iterate callback supplies this documented prefix
        // and retains the object's header/name storage during the callback.
        let (info, scan) = unsafe { (&*info, &mut *data.cast::<Scan>()) };
        let count = usize::from(info.dlpi_phnum);
        if info.dlpi_phdr.is_null() || count == 0 || count > 4096 {
            return 0;
        }
        let headers = unsafe { std::slice::from_raw_parts(info.dlpi_phdr, count) };
        let Some(image) = ProcessImage::from_phdrs(info.dlpi_addr as usize, headers) else {
            return 0;
        };
        if !image.contains(scan.address, true) || info.dlpi_name.is_null() {
            return 0;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(info.dlpi_name) }.to_bytes();
        if name.is_empty() || name.len() >= scan.name.len() {
            return 1;
        }
        scan.name[..name.len()].copy_from_slice(name);
        scan.image = Some(image);
        1
    }
    type Iterate = unsafe extern "C" fn(
        Option<unsafe extern "C" fn(*mut libc::dl_phdr_info, usize, *mut c_void) -> c_int>,
        *mut c_void,
    ) -> c_int;
    type Open = unsafe extern "C" fn(*const std::ffi::c_char, c_int) -> *mut c_void;
    type Info = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void) -> c_int;
    type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
    let iterate = crate::host_resolve::host_dl_iterate_phdr_cached()?;
    let open = crate::host_resolve::resolve_host_symbol_raw("dlopen")?;
    let info = crate::host_resolve::resolve_host_symbol_raw("dlinfo")?;
    let close = crate::host_resolve::resolve_host_symbol_raw("dlclose")?;
    // SAFETY: these addresses are host-owned entry points with the documented
    // C signatures. This entire preparation runs before cloning, on real host TLS.
    let (iterate, open, info, close) = unsafe {
        (
            std::mem::transmute::<usize, Iterate>(iterate),
            std::mem::transmute::<usize, Open>(open),
            std::mem::transmute::<usize, Info>(info),
            std::mem::transmute::<usize, Close>(close),
        )
    };
    let mut scan = Scan {
        address: prepare_native_public_tls_destructors as *const () as usize,
        image: None,
        name: [0; 4096],
    };
    unsafe { iterate(Some(collect), std::ptr::from_mut(&mut scan).cast()) };
    let image = scan.image?;
    let handle = unsafe {
        open(
            scan.name.as_ptr().cast(),
            libc::RTLD_NOW | libc::RTLD_NOLOAD,
        )
    };
    if handle.is_null() {
        return None;
    }
    let mut map: *mut c_void = std::ptr::null_mut();
    let result = unsafe {
        info(
            handle,
            libc::RTLD_DI_LINKMAP,
            std::ptr::from_mut(&mut map).cast(),
        )
    };
    // The public link_map prefix starts with l_addr. Verify the retained
    // object is the runtime we inspected, not another object with that name.
    if result != 0 || map.is_null() || unsafe { *map.cast::<usize>() } != image.base {
        unsafe { close(handle) };
        return None;
    }
    Some((image, handle as usize))
}

/// Called on a hosted creator before publishing a native child. Nested native
/// pthread_create never initializes this cache or enters the host loader.
pub(crate) fn prepare_native_public_tls_destructors() {
    if current_thread_handle().is_some() {
        return;
    }
    PROCESS_TLS_OWNERS.get_or_init(|| {
        let main = executable_image();
        let runtime_address = prepare_native_public_tls_destructors as *const () as usize;
        let mut owners = ProcessTlsOwners {
            main,
            runtime: None,
            _runtime_pin: 0,
        };
        if main
            .as_ref()
            .is_some_and(|image| image.contains(runtime_address, true))
        {
            return owners;
        }
        #[cfg(not(feature = "standalone"))]
        if let Some((image, pin)) = pin_runtime_image() {
            owners.runtime = Some(image);
            owners._runtime_pin = pin;
        }
        owners
    });
}

fn process_lifetime_address(address: usize, executable: bool) -> bool {
    PROCESS_TLS_OWNERS.get().is_some_and(|owners| {
        // GNU accepts a null owner for an executable callback. The callback's
        // own executable mapping still needs an independent lifetime proof.
        (!executable && address == 0 && owners.main.is_some())
            || owners
                .main
                .as_ref()
                .is_some_and(|image| image.contains(address, executable))
            || owners
                .runtime
                .as_ref()
                .is_some_and(|image| image.contains(address, executable))
    })
}

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
        Self {
            allocation: None,
            len: 0,
            capacity: 0,
            element: std::marker::PhantomData,
        }
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
        let capacity = self
            .capacity
            .checked_mul(2)
            .unwrap_or(needed)
            .max(needed)
            .max(4);
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
                std::ptr::copy(
                    self.as_ptr().add(index + 1),
                    self.as_ptr().add(index),
                    self.len - index - 1,
                )
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
        Self {
            hosted: Vec::new(),
            native: None,
        }
    }
}

impl<T> ThreadStorage<T> {
    fn native() -> Self {
        Self {
            hosted: Vec::new(),
            native: Some(MappedVec::new()),
        }
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
                header: RuntimeTlsState {
                    drain: drain_native,
                    reclaim: reclaim_native,
                },
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
            std::ptr::null_mut(),
            initialized.cast(),
            Ordering::AcqRel,
            Ordering::Acquire,
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
    if let Some(handle) = current_thread_handle() {
        let state = native_state(handle, true)?;
        // SAFETY: this native thread exclusively owns its ThreadHandle-pinned state.
        return callback(unsafe { &*state });
    }
    if use_tid_keyed_thread_exit() {
        let tid = current_exit_tid();
        let mut state = lookup_native_state(tid);
        if state.is_null() {
            let allocation = Box::new(ThreadState::default());
            state = Box::into_raw(allocation);
            if !NATIVE_PROCESS_EXIT.load(Ordering::Acquire) && !attach_reclaimer(state) {
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
    if let Some(handle) = current_thread_handle() {
        let state = native_state(handle, false)?;
        // SAFETY: this native thread exclusively owns its ThreadHandle-pinned state.
        return callback(unsafe { &*state });
    }
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
    // SAFETY: this thread owns `state` through the entire drain.
    drain(unsafe { &*state }, false);
}

fn drain_current() {
    if let Some(handle) = current_thread_handle() {
        if let Some(state) = native_state(handle, false) {
            drain_state(state);
        }
        return;
    }
    if use_tid_keyed_thread_exit() {
        drain_state(lookup_native_state(current_exit_tid()));
    } else {
        #[cfg(not(feature = "owned-tls-cache"))]
        {
            let _ = STATE.try_with(|slot| drain_state(slot.get()));
        }
    }
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
                    2,
                    std::ptr::from_ref(&blocked).cast(),
                    std::ptr::null_mut(),
                    std::mem::size_of::<u64>(),
                )
            }
            .is_err()
            {
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
#[cfg(not(feature = "standalone"))]
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

fn attach_reclaimer(state: *mut ThreadState) -> bool {
    #[cfg(feature = "standalone")]
    {
        attach_native_reclaimer(state)
    }
    #[cfg(not(feature = "standalone"))]
    {
        if current_thread_handle().is_some() {
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
    register_with_owner_policy(destructor, argument, dso_handle, false)
}

/// Public registration from a native worker uses the same queue and lifetime
/// pins as native DSOs. None means an ordinary hosted caller; -1 rejects an
/// unpinnable owner/provider instead of putting its callback on the creator's TCB.
pub(crate) fn register_native_public_tls_destructor(
    destructor: Destructor,
    argument: *mut c_void,
    dso_handle: *mut c_void,
) -> Option<c_int> {
    current_thread_handle()?;
    Some(
        if register_with_owner_policy(destructor, argument, dso_handle, true).is_some() {
            0
        } else {
            -1
        },
    )
}

fn registration_owner(
    dsos: &[NativeDso],
    address: usize,
    executable: bool,
    allow_process_images: bool,
) -> Option<Option<usize>> {
    if let Some(dso) = dsos.iter().find(|dso| {
        !dso.retiring
            && if executable {
                lifecycle::executable_address(dso, address)
            } else {
                contains_address(dso, address)
            }
    }) {
        return Some(Some(dso.id));
    }
    (allow_process_images && process_lifetime_address(address, executable)).then_some(None)
}

fn register_with_owner_policy(
    destructor: Destructor,
    argument: *mut c_void,
    dso_handle: *mut c_void,
    allow_process_images: bool,
) -> Option<()> {
    let _operation = OPERATIONS.lock();
    with_state(|state| {
        let mut entries = state.destructors.try_borrow_mut().ok()?;
        entries.try_reserve(1)?;
        let mut dsos = registry().lock().ok()?;
        let owner = registration_owner(&dsos, dso_handle as usize, false, allow_process_images)?;
        let provider = registration_owner(
            &dsos,
            destructor as *const () as usize,
            true,
            allow_process_images,
        )?;
        let mut owners = [0; 2];
        let mut owner_count = 0;
        for id in [owner, provider].into_iter().flatten() {
            if !owners[..owner_count].contains(&id) {
                owners[owner_count] = id;
                owner_count += 1;
            }
        }
        // Check all counts before changing any resident state. Once pinned,
        // the reserved queue slot cannot fail and owns exactly these pins.
        for id in &owners[..owner_count] {
            dsos.iter()
                .find(|dso| dso.id == *id)?
                .thread_exit_pins
                .checked_add(1)?;
        }
        for dso in dsos
            .iter_mut()
            .filter(|dso| owners[..owner_count].contains(&dso.id))
        {
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
    if owners.is_empty() {
        return;
    }
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
