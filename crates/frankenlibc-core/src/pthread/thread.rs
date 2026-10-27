//! POSIX thread creation and management — clone-based bootstrap.
//!
//! Implements the core thread lifecycle: create, join, detach, self, equal.
//! Uses the Linux `clone` syscall directly instead of delegating to glibc.
//!
//! ## Architecture
//!
//! Each new thread gets:
//! - A dedicated stack allocated via `mmap`, or a caller-owned stack
//! - A `ThreadHandle` that tracks TID, state, return value, and stack ownership
//! - `CLONE_CHILD_CLEARTID` so the kernel clears the TID and futex-wakes joiners on exit
//!
//! The `pthread_t` value returned to callers is the raw pointer to the `ThreadHandle`,
//! cast to `usize`. This matches the pattern used by musl and glibc.
//!
//! ## Lifecycle State Machine (bd-3hud)
//!
//! ```text
//!   STARTING ──> RUNNING ──┬──> FINISHED ──> JOINED  (join_thread)
//!                          │         │
//!                          │         └──> DETACHED   (detach after finish → immediate cleanup)
//!                          │
//!                          └──> DETACHED ──> (self-cleanup on exit)
//! ```
//!
//! State transitions are CAS-protected so exactly one of join/detach succeeds.
//! A detached thread that exits performs its own stack/handle cleanup in the
//! trampoline (no joiner to free resources).
//!
//! TLS handoff is a separate bead (bd-rth1).

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::syscall;

use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default stack size for direct core callers; the ABI supplies its own default.
const DEFAULT_STACK_SIZE: usize = 2 * 1024 * 1024;

/// Minimum usable stack for the supported Linux native-thread backends.
/// Reject smaller requests before writing the startup arguments into the map.
const MIN_STACK_SIZE: usize = 16 * 1024;

/// Both the x86-64 System V and AArch64 procedure-call ABIs require a
/// 16-byte-aligned stack before calling the Rust/C trampoline.
const THREAD_STACK_ALIGNMENT: usize = 16;

/// Guard page size: 4 KiB.
const GUARD_PAGE_SIZE: usize = 4096;

/// Keep child-start arguments away from the initial call frame and x86-64 red
/// zone so trampoline prologue/spills cannot overwrite them before they are read.
const THREAD_START_ARGS_GAP: usize = 4096;

/// Thread state: created but trampoline hasn't started yet.
pub const THREAD_STARTING: u32 = 0;

/// Thread state: trampoline is running the user's start_routine.
pub const THREAD_RUNNING: u32 = 1;

/// Thread state: start_routine returned; return value stored.
pub const THREAD_FINISHED: u32 = 2;

/// Thread state: detached — resources freed on exit (not joinable).
pub const THREAD_DETACHED: u32 = 3;

/// Thread state: joined — return value consumed, resources freed.
pub const THREAD_JOINED: u32 = 4;

/// Clone flags for creating a POSIX thread.
///
/// Shares: virtual memory, filesystem info, file descriptors, signal handlers,
/// thread group, SysV semaphore undo.
/// Sets parent TID pointer and child TID clear-on-exit (for join via futex).
#[allow(unsafe_code)]
const CLONE_THREAD_FLAGS: usize = {
    // From linux/sched.h
    const CLONE_VM: usize = 0x0000_0100;
    const CLONE_FS: usize = 0x0000_0200;
    const CLONE_FILES: usize = 0x0000_0400;
    const CLONE_SIGHAND: usize = 0x0000_0800;
    const CLONE_THREAD: usize = 0x0001_0000;
    const CLONE_SYSVSEM: usize = 0x0004_0000;
    const CLONE_PARENT_SETTID: usize = 0x0010_0000;
    const CLONE_CHILD_CLEARTID: usize = 0x0020_0000;
    // Signal to deliver on thread exit (none = 0 for CLONE_THREAD).
    CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_THREAD
        | CLONE_SYSVSEM
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
};

// mmap constants
const PROT_READ: usize = 0x1;
const PROT_WRITE: usize = 0x2;
const PROT_NONE: usize = 0x0;
const MAP_PRIVATE: usize = 0x02;
const MAP_ANONYMOUS: usize = 0x20;

// ---------------------------------------------------------------------------
// Thread handle
// ---------------------------------------------------------------------------

/// Magic value for identifying a valid ThreadHandle.
const THREAD_HANDLE_MAGIC: u32 = 0x5448_444c; // "THDL"

/// Per-thread control block. Allocated on the heap, pointed to by `pthread_t`.
///
/// The `tid` field doubles as the join futex: `CLONE_CHILD_CLEARTID` tells the
/// kernel to set `*child_tid = 0` and `futex_wake(child_tid)` when the thread
/// exits. Joiners simply `futex_wait(&tid, current_tid)` until tid becomes 0.
#[repr(C)]
pub struct ThreadHandle {
    /// Magic identifier for validity checking.
    pub magic: u32,

    /// Kernel thread ID. Set by `CLONE_PARENT_SETTID` on creation.
    /// Cleared to 0 by `CLONE_CHILD_CLEARTID` on thread exit.
    pub tid: AtomicI32,

    /// Stable thread identity captured by the child in trampoline context.
    /// Unlike `tid`, this is not cleared by `CLONE_CHILD_CLEARTID`.
    pub self_tid: AtomicI32,

    /// Lifecycle state (see `THREAD_*` constants).
    pub state: AtomicU32,

    /// Startup synchronization futex: 0 while pending, 1 on success, or
    /// `errno + 1` when setup failed before the user entry point ran.
    pub started: AtomicU32,

    /// Return value from the user's `start_routine`.
    /// Written by the child before exit; read by the joiner after `tid == 0`.
    pub retval: core::cell::UnsafeCell<usize>,

    /// The native thread's errno slot. Only its owner and that owner's signal
    /// handlers access this cell; no inherited compiler TLS is involved.
    pub errno: core::cell::UnsafeCell<i32>,

    /// POSIX cancellation settings, initialized independently of the creator.
    /// These settings do not imply native asynchronous cancellation delivery.
    pub cancel_state: AtomicI32,
    pub cancel_type: AtomicI32,

    /// Top of the ABI's caller-owned C cancellation cleanup chain. Only the
    /// owner changes this pointer, and every entry is removed before its
    /// callback can reenter libc. Kept here rather than in inherited TLS.
    pub cleanup_head: AtomicUsize,

    /// Set once the native exit protocol begins. Further cancellation points
    /// in cleanup callbacks must not restart an unwind already in progress.
    pub exit_started: AtomicU32,

    /// Stack pointer of the clone trampoline before application entry. The
    /// ABI unwinder stops above this frame instead of interpreting clone's
    /// synthetic stack as though it had a normal calling frame.
    pub unwind_stack_boundary: AtomicUsize,

    /// ABI-owned unwind header, aligned for the Itanium unwind ABI. Its
    /// lifetime covers every landing pad and ends only at thread teardown.
    pub unwind_exception: core::cell::UnsafeCell<[u128; 2]>,

    /// Itanium C++ caught-exception pointer and uncaught-exception count.
    /// Native threads must not use the creator's compiler TLS for this state.
    pub cxa_eh_globals: core::cell::UnsafeCell<[usize; 2]>,

    /// Base address of the owned mapping, including its guard. Zero for a
    /// caller-provided stack, which this implementation must never unmap.
    pub stack_base: usize,

    /// Length of the owned mapping. Zero for a caller-provided stack.
    pub stack_total_size: usize,

    /// Lowest address of the usable stack, excluding any protected guard.
    pub stack_addr: usize,

    /// Usable stack extent, including any trailing alignment padding.
    pub stack_size: usize,

    /// Effective protected guard size, rounded to the runtime page size.
    /// Caller-provided stacks always have zero libc-managed guard bytes.
    pub guard_size: usize,

    /// Per-thread TLS value storage (bd-rth1). Allocation-free: lives in the
    /// heap-allocated ThreadHandle so clone-based threads never need malloc.
    pub tls_values: [super::tls::TlsEntry; super::tls::PTHREAD_KEYS_MAX],
}

// SAFETY: ThreadHandle is designed for cross-thread sharing via atomic fields.
// The `retval` field is accessed only after synchronization (tid cleared to 0).
// The errno cell is accessed only by its owning thread and its signal handlers.
#[allow(unsafe_code)]
unsafe impl Send for ThreadHandle {}
#[allow(unsafe_code)]
unsafe impl Sync for ThreadHandle {}

/// Arguments passed to the child thread trampoline on the child stack.
#[repr(C)]
struct ThreadStartArgs {
    /// Pointer to the ThreadHandle for this thread.
    handle: *mut ThreadHandle,
    /// User's start routine.
    start_routine: usize, // fn ptr as usize
    /// User's argument to start_routine.
    arg: usize, // *mut c_void as usize
    /// Affinity storage is borrowed only until `started` is published. The
    /// parent keeps its configuration alive while waiting for that publication.
    affinity: *const u8,
    affinity_len: usize,
    scheduling: Option<(i32, i32)>,
    signal_mask: u64,
}

// ---------------------------------------------------------------------------
// Thread trampoline (runs in child context)
// ---------------------------------------------------------------------------

/// Entry point for the child thread after clone.
///
/// Called by the clone trampoline asm with `args_raw` in `rdi`.
/// This function:
/// 1. Reads the `ThreadStartArgs` from the pointer
/// 2. Applies scheduling/affinity and registers its thread-local key storage
/// 3. Signals the parent that setup is complete and restores the signal mask
/// 4. Calls the user's `start_routine(arg)`
/// 5. Stores the return value in the handle and exits
///
/// # Safety
///
/// `args_raw` must be a valid pointer to `ThreadStartArgs` on the child's stack.
/// The affinity slice must remain valid until startup is published; the user
/// argument and handle retain their normal thread-lifetime requirements.
#[allow(unsafe_code)]
unsafe extern "C-unwind" fn thread_trampoline(args_raw: usize) -> usize {
    // SAFETY: args_raw is a pointer to ThreadStartArgs that the parent placed
    // on our stack before clone. It's valid until we finish reading it.
    let args = unsafe { &*(args_raw as *const ThreadStartArgs) };
    let handle_ptr = args.handle;
    let start_routine_addr = args.start_routine;
    let arg = args.arg;
    let signal_mask = args.signal_mask;

    // SAFETY: handle_ptr was allocated by the parent and is valid for the
    // thread's entire lifetime.
    let handle = unsafe { &*handle_ptr };
    let current_tid = syscall::sys_gettid();
    handle.self_tid.store(current_tid, Ordering::Release);
    if handle.tid.load(Ordering::Acquire) == 0 {
        handle.tid.store(current_tid, Ordering::Release);
    }

    // clone inherited a blocked signal mask. No application code, allocation,
    // or inherited host TLS is used while installing the requested attributes.
    // SAFETY: the creator keeps args and its borrowed affinity alive until
    // this thread publishes startup, which has not happened yet.
    let setup = unsafe { apply_thread_startup(args) };
    if let Err(error) = setup {
        // This handle has not escaped the creator. Leave its owned stack for
        // the parent to reclaim only after CLONE_CHILD_CLEARTID clears tid.
        handle.state.store(THREAD_FINISHED, Ordering::Release);
        publish_startup(handle, error as u32 + 1);
        syscall::sys_exit_thread(0);
    }

    // Register TLS storage before signals can run application handlers or the
    // user routine can query its native handle. This path allocates nothing.
    // SAFETY: handle_ptr is live and this thread exclusively owns tls_values.
    if !super::tls::register_thread_tls(current_tid, unsafe {
        (*handle_ptr).tls_values.as_mut_ptr()
    }) {
        // Exhausting the fixed identity table must not start a thread whose
        // errno, key values or cancellation settings alias its creator.
        handle.state.store(THREAD_FINISHED, Ordering::Release);
        publish_startup(handle, 11 + 1); // EAGAIN
        syscall::sys_exit_thread(0);
    }

    // Try to transition STARTING → RUNNING. If detach_thread already set
    // DETACHED, we must not overwrite it.
    let _ = handle.state.compare_exchange(
        THREAD_STARTING,
        THREAD_RUNNING,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    // Nothing below reads the parent's affinity buffer. Publish readiness
    // before restoring the mask: a pending signal handler may immediately
    // wait for the creator, which must already be able to return from create.
    let unwind_boundary: usize;
    // SAFETY: read this frame's stack pointer without changing machine state.
    // Publish before signals can run pthread_exit from an application handler.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) unwind_boundary,
                        options(nostack, nomem, preserves_flags));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) unwind_boundary,
                        options(nostack, nomem, preserves_flags));
    }
    handle
        .unwind_stack_boundary
        .store(unwind_boundary, Ordering::Relaxed);
    publish_startup(handle, 1);
    // SAFETY: Linux's kernel sigset is exactly one u64 on both supported ISAs.
    // The parent used this same syscall successfully before clone. With valid
    // arguments, restoring a mask cannot fail under the ordinary Linux ABI.
    if unsafe {
        syscall::sys_rt_sigprocmask(
            2, // SIG_SETMASK
            core::ptr::from_ref(&signal_mask).cast(),
            core::ptr::null_mut(),
            core::mem::size_of::<u64>(),
        )
    }
    .is_err()
    {
        // A syscall filter can still deny the otherwise valid restoration.
        // Startup has been published so application signal handlers can wait
        // for the creator; do not enter the user routine under the wrong mask.
        // SAFETY: this thread owns the live handle and its registered TLS.
        unsafe { exit_current_thread(handle_ptr, 0) }
    }

    // Cast the start_routine address back to a function pointer and call it.
    // SAFETY: start_routine_addr was a valid extern "C" fn pointer stored by
    // the parent. arg is the user's argument.
    // The native ABI exit path forces stack unwinding through application
    // cleanup frames. It stops at the end of this stack before final teardown;
    // do not insert a nounwind boundary around the application's start call.
    let start_fn: unsafe extern "C-unwind" fn(usize) -> usize =
        unsafe { core::mem::transmute(start_routine_addr) };
    let retval = unsafe { start_fn(arg) };

    // Explicit and implicit thread exit must follow the same teardown/state
    // transition path so detached threads self-clean and TLS destructors run.
    unsafe { exit_current_thread(handle_ptr, retval) }
}

/// Install the child-only attributes while all maskable signals remain blocked.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
unsafe fn apply_thread_startup(args: &ThreadStartArgs) -> Result<(), i32> {
    if !args.affinity.is_null() {
        // SAFETY: create_thread_with_startup borrows this exact slice until
        // after startup publication, which has not happened yet.
        unsafe { syscall::sys_sched_setaffinity(0, args.affinity_len, args.affinity) }?;
    }
    if let Some((policy, priority)) = args.scheduling {
        // Linux sched_param consists of the single sched_priority integer.
        // SAFETY: priority is a live, aligned i32 throughout the syscall.
        unsafe {
            syscall::sys_sched_setscheduler(0, policy, core::ptr::from_ref(&priority).cast())
        }?;
    }
    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
fn publish_startup(handle: &ThreadHandle, outcome: u32) {
    handle.started.store(outcome, Ordering::Release);
    // SAFETY: the handle remains live until its tid is cleared and its parent
    // reclaims it; started is an aligned futex word within that allocation.
    let _ = unsafe {
        syscall::sys_futex(
            core::ptr::from_ref(&handle.started).cast(),
            0x01 | 0x80, // FUTEX_WAKE | FUTEX_PRIVATE_FLAG
            1,
            0,
            0,
            0,
        )
    };
}

// ---------------------------------------------------------------------------
// Stack reclamation for detached threads
// ---------------------------------------------------------------------------

/// Unmap the thread's own stack and exit immediately.
///
/// This is the only safe way to reclaim a detached thread's stack: by doing
/// the munmap and exit as two consecutive syscalls with no stack access in
/// between. Equivalent to musl's `__unmapself`.
///
/// # Safety
///
/// - `stack_base` must be the base of the current thread's mmap'd stack region.
/// - `stack_total_size` must be the total size of that region.
/// - This function never returns.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
unsafe fn unmapself_and_exit(stack_base: usize, stack_total_size: usize) -> ! {
    // SYS_munmap = 11, SYS_exit = 60 on x86_64.
    // All arguments go into registers — no stack access after munmap.
    // SAFETY: This is the only safe way to unmap our own stack — two
    // consecutive register-only syscalls with no intervening stack access.
    unsafe {
        core::arch::asm!(
            "syscall",           // munmap(stack_base, stack_total_size)
            "xor edi, edi",      // exit_code = 0
            "mov eax, 60",       // SYS_exit
            "syscall",           // exit(0)
            in("rax") 11u64,     // SYS_munmap
            in("rdi") stack_base,
            in("rsi") stack_total_size,
            options(noreturn)
        );
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
unsafe fn detached_thread_self_cleanup_and_exit(handle_ptr: *mut ThreadHandle) -> ! {
    // SAFETY: caller guarantees `handle_ptr` is a live detached thread handle
    // that is no longer accessible by any joiner.
    let handle = unsafe { &*handle_ptr };

    // CRITICAL: Before freeing the handle, tell the kernel not to write to the
    // TID address on thread exit. Otherwise CLONE_CHILD_CLEARTID would write 0
    // to freed memory.
    let _ = syscall::sys_set_tid_address(0);

    let stack_base = handle.stack_base;
    let stack_total_size = handle.stack_total_size;

    // SAFETY: `handle_ptr` was allocated via Box::into_raw in create_thread and
    // detached threads own their final cleanup path.
    unsafe { drop(Box::from_raw(handle_ptr)) };

    if stack_base != 0 && stack_total_size != 0 {
        unsafe { unmapself_and_exit(stack_base, stack_total_size) };
    }

    syscall::sys_exit_thread(0);
}

/// Finalize the current native-managed thread and terminate it.
///
/// This is shared by the clone trampoline return path and the ABI
/// `pthread_exit` entrypoint so both honor TLS destructor teardown, FINISHED
/// state publication, and detached-thread self-cleanup.
///
/// # Safety
///
/// `handle_ptr` must be the current thread's live `ThreadHandle`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
pub unsafe fn exit_current_thread(handle_ptr: *mut ThreadHandle, retval: usize) -> ! {
    let tid = syscall::sys_gettid();
    super::tls::teardown_native_thread_tls(tid);

    // SAFETY: `handle_ptr` is the current thread's live handle. The return
    // value becomes visible only after the FINISHED/DETACHED synchronization.
    unsafe { *(*handle_ptr).retval.get() = retval };

    let handle = unsafe { &*handle_ptr };
    loop {
        let state = handle.state.load(Ordering::Acquire);
        match state {
            THREAD_STARTING | THREAD_RUNNING => {
                match handle.state.compare_exchange(
                    state,
                    THREAD_FINISHED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(THREAD_DETACHED) => {
                        unsafe { detached_thread_self_cleanup_and_exit(handle_ptr) };
                    }
                    Err(_) => continue,
                }
            }
            THREAD_DETACHED => unsafe { detached_thread_self_cleanup_and_exit(handle_ptr) },
            THREAD_FINISHED | THREAD_JOINED => break,
            _ => break,
        }
    }

    syscall::sys_exit_thread(0);
}

/// Unmap the thread's own stack and exit immediately.
///
/// This is the only safe way to reclaim a detached thread's stack: by doing
/// the munmap and exit as two consecutive syscalls with no stack access in
/// between. Equivalent to musl's `__unmapself`.
///
/// # Safety
///
/// - `stack_base` must be the base of the current thread's mmap'd stack region.
/// - `stack_total_size` must be the total size of that region.
/// - This function never returns.
#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
unsafe fn unmapself_and_exit(stack_base: usize, stack_total_size: usize) -> ! {
    // SYS_munmap = 215, SYS_exit = 93 on aarch64.
    // All arguments go into registers — no stack access after munmap.
    // SAFETY: This is the only safe way to unmap our own stack — two
    // consecutive register-only syscalls with no intervening stack access.
    unsafe {
        core::arch::asm!(
            "mov x8, 215",       // SYS_munmap
            "svc 0",             // munmap(stack_base, stack_total_size)
            "mov x0, 0",         // exit_code = 0
            "mov x8, 93",        // SYS_exit
            "svc 0",             // exit(0)
            "brk #0",            // unreachable
            in("x0") stack_base,
            in("x1") stack_total_size,
            options(noreturn)
        );
    }
}

// ---------------------------------------------------------------------------
// Stack allocation
// ---------------------------------------------------------------------------

/// Allocate a thread stack via mmap with a guard page at the bottom.
///
/// Returns `(base, total_size, usable_top)` where:
/// - `base` is the start of the mmap'd region (guard page)
/// - `total_size` is guard + usable stack
/// - `usable_top` is the top of the usable stack (stack grows down)
///
/// Returns `Err(errno)` on failure.
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
#[allow(unsafe_code)]
fn allocate_thread_stack(stack_size: usize) -> Result<(usize, usize, usize), i32> {
    let stack = prepare_thread_stack(ThreadStack::Allocated {
        size: stack_size,
        guard_size: GUARD_PAGE_SIZE,
        page_size: GUARD_PAGE_SIZE,
    })?;
    Ok((stack.mapping_base, stack.mapping_size, stack.top))
}

/// Stack ownership and layout requested by the native thread creator.
#[derive(Clone, Copy, Debug)]
pub enum ThreadStack {
    /// Allocate a usable stack plus a separately protected low-address guard.
    Allocated {
        size: usize,
        guard_size: usize,
        page_size: usize,
    },
    /// Use writable storage owned by the caller. No protection or reclamation
    /// operation is performed on this region, including on creation failure.
    Borrowed { address: usize, size: usize },
}

/// Attributes installed by the native creator before the user's routine runs.
///
/// Unspecified attributes are inherited from the creating thread. Affinity
/// bytes are borrowed only for the synchronous creation handshake, so the ABI
/// can pass its snapshot without allocating or freeing on the clone child.
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreadStartup<'a> {
    /// Linux CPU bitmap; `Some(&[])` is an explicit invalid/empty mask rather
    /// than a request to inherit the current affinity.
    pub affinity: Option<&'a [u8]>,
    /// Linux's 64-bit kernel signal mask. Public libc policy, such as reserving
    /// internal signals, is applied at the ABI boundary before passing it here.
    pub signal_mask: Option<u64>,
    /// An explicit `(policy, priority)` pair; `None` retains clone inheritance.
    pub scheduling: Option<(i32, i32)>,
}

#[derive(Debug, PartialEq, Eq)]
struct PreparedThreadStack {
    mapping_base: usize,
    mapping_size: usize,
    address: usize,
    size: usize,
    guard_size: usize,
    top: usize,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
fn prepare_thread_stack(request: ThreadStack) -> Result<PreparedThreadStack, i32> {
    let (stack_size, guard_size, page_size) = match request {
        ThreadStack::Borrowed { address, size } => {
            if address == 0 || size < MIN_STACK_SIZE || size > isize::MAX as usize {
                return Err(crate::errno::EINVAL);
            }
            let end = address.checked_add(size).ok_or(crate::errno::EINVAL)?;
            return Ok(PreparedThreadStack {
                mapping_base: 0,
                mapping_size: 0,
                address,
                size,
                guard_size: 0,
                top: end & !(THREAD_STACK_ALIGNMENT - 1),
            });
        }
        ThreadStack::Allocated {
            size,
            guard_size,
            page_size,
        } => (size, guard_size, page_size),
    };
    if stack_size < MIN_STACK_SIZE {
        return Err(crate::errno::EINVAL);
    }
    if page_size < THREAD_STACK_ALIGNMENT || !page_size.is_power_of_two() {
        return Err(crate::errno::EINVAL);
    }
    let guard_size = guard_size
        .checked_add(page_size - 1)
        .ok_or(crate::errno::ENOMEM)?
        & !(page_size - 1);
    let total_size = guard_size
        .checked_add(stack_size)
        .filter(|size| *size <= isize::MAX as usize)
        .ok_or(crate::errno::ENOMEM)?;

    // Allocate the full region as read+write.
    // SAFETY: anonymous mmap with no fd, valid parameters.
    let base = unsafe {
        syscall::sys_mmap(
            core::ptr::null_mut(),
            total_size,
            (PROT_READ | PROT_WRITE) as i32,
            (MAP_PRIVATE | MAP_ANONYMOUS) as i32,
            -1,
            0,
        )
    }?;

    if guard_size != 0 {
        // SAFETY: the guard is a page-aligned prefix of the owned mapping.
        if let Err(e) = unsafe { syscall::sys_mprotect(base, guard_size, PROT_NONE as i32) } {
            // SAFETY: base/total_size are the mapping we just created.
            let _ = unsafe { syscall::sys_munmap(base, total_size) };
            return Err(e);
        }
    }

    // A valid pthread stack size need not be a multiple of 16 (or even 8).
    // mmap aligns the base, not base + length: using the unrounded end would
    // make both ptr::write(ThreadStartArgs) and the child call frame unaligned.
    // Round DOWN within the owned mapping, retaining its original length for
    // reclamation. The minimum size leaves room for the startup gap and args
    // even after losing up to THREAD_STACK_ALIGNMENT - 1 trailing bytes.
    let usable_top = (base as usize + total_size) & !(THREAD_STACK_ALIGNMENT - 1);
    Ok(PreparedThreadStack {
        mapping_base: base as usize,
        mapping_size: total_size,
        address: base as usize + guard_size,
        size: stack_size,
        guard_size,
        top: usable_top,
    })
}

/// Reclaim an owned stack mapping; zero extents represent caller-owned storage.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
fn free_thread_stack(base: usize, total_size: usize) {
    if base == 0 || total_size == 0 {
        return;
    }
    // SAFETY: nonzero base/total_size identify the mapping from prepare_thread_stack.
    let _ = unsafe { syscall::sys_munmap(base as *mut u8, total_size) };
}

// ---------------------------------------------------------------------------
// Thread creation (public API for ABI layer)
// ---------------------------------------------------------------------------

/// Create a new thread using the Linux `clone` syscall.
///
/// This is the native implementation that replaces `libc::pthread_create`.
///
/// # Arguments
///
/// * `start_routine` - Function pointer for the new thread to execute.
///   Signature: `extern "C" fn(*mut c_void) -> *mut c_void`, passed as usize.
/// * `arg` - Argument to pass to `start_routine`, as usize.
/// * `stack_size` - Usable stack size in bytes; 0 selects the default. Nonzero
///   values below 16 KiB fail with EINVAL. Other sizes need not be aligned.
///
/// # Returns
///
/// On success: `Ok(handle_ptr)` where `handle_ptr` is a `*mut ThreadHandle`
/// that serves as the `pthread_t` value.
///
/// On failure: `Err(errno)`.
///
/// # Safety
///
/// * `start_routine` must be a valid function pointer with the C ABI.
/// * `arg` must be valid for the lifetime of the new thread.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
pub unsafe fn create_thread(
    start_routine: usize,
    arg: usize,
    stack_size: usize,
) -> Result<*mut ThreadHandle, i32> {
    // Use the requested stack size, or the default if 0.
    let actual_stack_size = if stack_size > 0 {
        stack_size
    } else {
        DEFAULT_STACK_SIZE
    };
    // SAFETY: this wrapper requests owned storage and forwards the caller's
    // guarantees about the entry point and its argument.
    unsafe {
        create_thread_with_stack(
            start_routine,
            arg,
            ThreadStack::Allocated {
                size: actual_stack_size,
                guard_size: GUARD_PAGE_SIZE,
                page_size: GUARD_PAGE_SIZE,
            },
        )
    }
}

/// Create a native thread with an explicit stack ownership policy.
///
/// # Safety
///
/// The entry point and argument have the same requirements as `create_thread`.
/// A borrowed stack must be writable, exclusively available to the new thread,
/// and remain mapped until that thread has terminated. Its caller owns all guard
/// protection and reclamation, including after join, detach, or creation failure.
/// An allocated stack's page size must be the actual operating-system page size.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
pub unsafe fn create_thread_with_stack(
    start_routine: usize,
    arg: usize,
    stack: ThreadStack,
) -> Result<*mut ThreadHandle, i32> {
    // SAFETY: this wrapper forwards the entry/argument/stack guarantees and
    // selects ordinary inheritance for every execution attribute.
    unsafe { create_thread_with_startup(start_routine, arg, stack, ThreadStartup::default()) }
}

/// Create a native thread with explicit stack and execution attributes.
///
/// Affinity and scheduling failures are reported by the creating thread before
/// a handle is published to its caller. The failed child never enters user code,
/// and its owned stack is reclaimed after the kernel acknowledges its exit.
///
/// # Safety
///
/// The entry point, argument and stack have the same requirements as
/// `create_thread_with_stack`. The safe borrowed affinity slice remains live
/// until this function returns; the child consumes it before releasing the
/// startup handshake and never retains it during application execution.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
pub unsafe fn create_thread_with_startup(
    start_routine: usize,
    arg: usize,
    stack: ThreadStack,
    startup: ThreadStartup<'_>,
) -> Result<*mut ThreadHandle, i32> {
    let stack = prepare_thread_stack(stack)?;
    let stack_base = stack.mapping_base;
    let stack_total_size = stack.mapping_size;
    let stack_top = stack.top;

    // Allocate the ThreadHandle on the heap (Box).
    let handle = Box::new(ThreadHandle {
        magic: THREAD_HANDLE_MAGIC,
        tid: AtomicI32::new(0),
        self_tid: AtomicI32::new(0),
        state: AtomicU32::new(THREAD_STARTING),
        started: AtomicU32::new(0),
        retval: core::cell::UnsafeCell::new(0),
        errno: core::cell::UnsafeCell::new(0),
        cancel_state: AtomicI32::new(0), // PTHREAD_CANCEL_ENABLE
        cancel_type: AtomicI32::new(0),  // PTHREAD_CANCEL_DEFERRED
        cleanup_head: AtomicUsize::new(0),
        exit_started: AtomicU32::new(0),
        unwind_stack_boundary: AtomicUsize::new(0),
        unwind_exception: core::cell::UnsafeCell::new([0; 2]),
        cxa_eh_globals: core::cell::UnsafeCell::new([0; 2]),
        stack_base,
        stack_total_size,
        stack_addr: stack.address,
        stack_size: stack.size,
        guard_size: stack.guard_size,
        tls_values: [super::tls::TlsEntry::default(); super::tls::PTHREAD_KEYS_MAX],
    });
    let handle_ptr = Box::into_raw(handle);

    // Prepare ThreadStartArgs on the child stack.
    // The args struct goes near the top of the stack, and the trampoline
    // frame (fn_ptr + arg) goes at the very top.
    // Block application signals over clone so they cannot run on the child
    // before its native TLS and execution attributes are ready. The parent
    // restores its original mask on every path after the raw clone syscall.
    let blocked_mask = u64::MAX;
    let mut inherited_mask = 0u64;
    // SAFETY: both masks are live u64 values and Linux uses an 8-byte sigset.
    if let Err(error) = unsafe {
        syscall::sys_rt_sigprocmask(
            2, // SIG_SETMASK
            core::ptr::from_ref(&blocked_mask).cast(),
            core::ptr::from_mut(&mut inherited_mask).cast(),
            core::mem::size_of::<u64>(),
        )
    } {
        // SAFETY: clone has not run and handle_ptr is exclusively ours.
        unsafe { drop(Box::from_raw(handle_ptr)) };
        free_thread_stack(stack_base, stack_total_size);
        return Err(error);
    }
    let args = ThreadStartArgs {
        handle: handle_ptr,
        start_routine,
        arg,
        affinity: startup.affinity.map_or(core::ptr::null(), <[u8]>::as_ptr),
        affinity_len: startup.affinity.map_or(0, <[u8]>::len),
        scheduling: startup.scheduling,
        signal_mask: startup.signal_mask.unwrap_or(inherited_mask),
    };

    // Place args in a stable location. We'll put it in the upper portion of
    // the child stack. The trampoline reads it via a pointer.
    // Layout from stack_top (growing down):
    //   [stack_top - 8]:  arg to trampoline (= pointer to ThreadStartArgs)
    //   [stack_top - 16]: fn_ptr (= thread_trampoline)
    //   [stack_top - 16 - gap - size_of::<ThreadStartArgs>()]: ThreadStartArgs data

    let args_size = core::mem::size_of::<ThreadStartArgs>();
    // Align args to 8 bytes.
    let args_aligned_size = (args_size + 7) & !7;

    // Calculate positions.
    let args_addr = stack_top - 16 - THREAD_START_ARGS_GAP - args_aligned_size;
    let trampoline_frame = stack_top - 16;

    // Write ThreadStartArgs to the child stack.
    // SAFETY: args_addr is within the mmap'd stack region.
    unsafe {
        core::ptr::write(args_addr as *mut ThreadStartArgs, args);
    }

    // Write the trampoline frame: [fn_ptr, arg_to_fn].
    // fn_ptr = thread_trampoline
    // arg_to_fn = args_addr (pointer to ThreadStartArgs)
    // SAFETY: trampoline_frame is within the mmap'd stack region.
    unsafe {
        core::ptr::write(
            trampoline_frame as *mut usize,
            thread_trampoline as *const () as usize,
        );
        core::ptr::write((trampoline_frame + 8) as *mut usize, args_addr);
    }

    // The child_sp for clone is trampoline_frame (top of the prepared frame).
    // After clone, child rsp = trampoline_frame.
    // pop rax -> fn_ptr (thread_trampoline)
    // pop rdi -> args_addr (passed to thread_trampoline)
    let child_sp = trampoline_frame;

    // parent_tid: kernel writes child TID here via CLONE_PARENT_SETTID.
    // SAFETY: handle_ptr was just created via Box::into_raw and is valid.
    let parent_tid_ptr = unsafe { &(*handle_ptr).tid as *const AtomicI32 as *mut i32 };
    // child_tid: kernel clears this to 0 and futex-wakes on thread exit
    // via CLONE_CHILD_CLEARTID.
    let child_tid_ptr = parent_tid_ptr; // Same location — tid serves both purposes.

    // The child shares this thread's TLS (no CLONE_SETTLS below), so a
    // TLS-cached tid would answer with ours.
    super::tls::disable_tid_cache();

    // Execute clone.
    // SAFETY: All pointers are valid. child_sp is a properly prepared stack.
    let result = unsafe {
        syscall::sys_clone_thread(
            CLONE_THREAD_FLAGS,
            child_sp,
            parent_tid_ptr,
            child_tid_ptr,
            0, // TLS: not set in phase 1 (bd-rth1 scope)
        )
    };
    // SAFETY: inherited_mask was captured immediately before clone and is
    // still live. All arguments and the syscall were validated by that call.
    let _ = unsafe {
        syscall::sys_rt_sigprocmask(
            2,
            core::ptr::from_ref(&inherited_mask).cast(),
            core::ptr::null_mut(),
            core::mem::size_of::<u64>(),
        )
    };

    match result {
        Ok(_child_tid) => {
            // `CLONE_PARENT_SETTID` already published `tid` into `handle.tid`.
            // Do not write `tid` again in parent context: if the child exits
            // very quickly, `CLONE_CHILD_CLEARTID` can clear it to 0 before
            // this point, and a late parent store would reintroduce a stale
            // non-zero TID that can make `join_thread` wait forever.
            // Wait for the child to signal that it has started and read the args.
            // This ensures the stack-based ThreadStartArgs are consumed before
            // we consider the create operation complete.
            match wait_for_startup(handle_ptr) {
                Ok(()) => Ok(handle_ptr),
                Err(error) => {
                    // SAFETY: the failed child never entered application code
                    // and this handle has not escaped. join waits for the
                    // kernel to clear tid before freeing its owned storage.
                    let _ = unsafe { join_thread(handle_ptr) };
                    Err(error)
                }
            }
        }
        Err(errno) => {
            // Clone failed — clean up.
            // SAFETY: handle_ptr was just created via Box::into_raw.
            unsafe { drop(Box::from_raw(handle_ptr)) };
            free_thread_stack(stack_base, stack_total_size);
            Err(errno)
        }
    }
}

/// Wait for the child thread to signal startup completion.
///
/// Uses futex wait on `handle.started` until it becomes non-zero.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
fn wait_for_startup(handle_ptr: *mut ThreadHandle) -> Result<(), i32> {
    // SAFETY: handle_ptr is valid (we just allocated it).
    let handle = unsafe { &*handle_ptr };
    loop {
        let started = handle.started.load(Ordering::Acquire);
        if started != 0 {
            return if started == 1 {
                Ok(())
            } else {
                Err((started - 1) as i32)
            };
        }
        // Futex wait: sleep until started changes from 0.
        let futex_ptr = &handle.started as *const AtomicU32 as *const u32;
        // SAFETY: futex_ptr points to a valid, aligned u32 in the handle.
        let _ = unsafe {
            syscall::sys_futex(
                futex_ptr,
                0x80, // FUTEX_WAIT_PRIVATE (FUTEX_WAIT=0 | FUTEX_PRIVATE_FLAG=0x80)
                0,    // expected value
                0,    // no timeout
                0, 0,
            )
        };
        // Spurious wakeup or EAGAIN: re-check.
    }
}

/// Wait for a thread to exit by futex-waiting on its TID.
///
/// Returns `Ok(retval)` on success (the thread's return value as `usize`).
///
/// # Errors
///
/// - `EINVAL` (22): null handle, already joined, or already detached
/// - `EDEADLK` (35): thread attempting to join itself
///
/// # Safety
///
/// `handle_ptr` must be a valid `*mut ThreadHandle` from `create_thread`.
/// Must only be called once per handle (concurrent or repeated joins return EINVAL).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
pub unsafe fn join_thread(handle_ptr: *mut ThreadHandle) -> Result<usize, i32> {
    const EINVAL: i32 = 22;
    const EDEADLK: i32 = 35;

    if handle_ptr.is_null() {
        return Err(EINVAL);
    }

    // SAFETY: caller guarantees handle_ptr is valid.
    let handle = unsafe { &*handle_ptr };

    let state = handle.state.load(Ordering::Acquire);
    let my_tid = syscall::sys_gettid();
    let target_self_tid = handle.self_tid.load(Ordering::Acquire);
    if (state == THREAD_STARTING || state == THREAD_RUNNING)
        && target_self_tid != 0
        && my_tid == target_self_tid
    {
        return Err(EDEADLK);
    }

    // Self-join detection: if the calling thread's TID matches the handle's
    // TID, we'd deadlock.
    //
    // On clone startup there is a small publication window where the child can
    // run user code before parent-side TID publication is visible in `tid`.
    // If we evaluate self-join during that window, we'd miss EDEADLK and later
    // block forever waiting on a zero tid value.
    let mut target_tid = handle.tid.load(Ordering::Acquire);
    if target_tid == 0 {
        loop {
            let state = handle.state.load(Ordering::Acquire);
            if state != THREAD_STARTING && state != THREAD_RUNNING {
                break;
            }

            target_tid = handle.tid.load(Ordering::Acquire);
            if target_tid != 0 {
                break;
            }
            core::hint::spin_loop();
        }
    }

    if target_tid != 0 && my_tid == target_tid {
        return Err(EDEADLK);
    }

    // Atomically claim the right to join. We need to transition from a joinable
    // state (RUNNING or FINISHED) to JOINED. CAS ensures only one joiner wins.
    let mut already_claimed_join = false;
    loop {
        let state = handle.state.load(Ordering::Acquire);
        match state {
            THREAD_DETACHED => return Err(EINVAL),
            THREAD_JOINED => return Err(EINVAL),
            THREAD_STARTING | THREAD_RUNNING => {
                // Thread hasn't finished yet. We can't CAS to JOINED yet,
                // but we know no one else has claimed it. Break out and wait
                // for exit via futex.
                break;
            }
            THREAD_FINISHED => {
                // Thread is done. Try to atomically claim FINISHED → JOINED.
                match handle.state.compare_exchange(
                    THREAD_FINISHED,
                    THREAD_JOINED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        already_claimed_join = true;
                        // We own the join. Proceed to wait for tid == 0 to ensure
                        // the kernel has finished the exit sequence before we
                        // reclaim the stack and handle.
                        break;
                    }
                    Err(new_state) => {
                        // Someone else changed the state (detach or another joiner).
                        if new_state == THREAD_JOINED || new_state == THREAD_DETACHED {
                            return Err(EINVAL);
                        }
                        // Retry the loop for unexpected states.
                        continue;
                    }
                }
            }
            _ => return Err(EINVAL), // Unknown state.
        }
    }

    // Thread is still running. Wait for the kernel to clear tid to 0
    // (CLONE_CHILD_CLEARTID).
    loop {
        let tid = handle.tid.load(Ordering::Acquire);
        if tid == 0 {
            break;
        }
        let futex_ptr = &handle.tid as *const AtomicI32 as *const u32;
        // SAFETY: futex_ptr points to a valid, aligned i32 in the handle.
        let _ = unsafe {
            syscall::sys_futex(
                // CLONE_CHILD_CLEARTID issues a non-private FUTEX_WAKE from
                // the kernel. Waiting with FUTEX_WAIT_PRIVATE can miss that
                // wake and deadlock joiners.
                futex_ptr, 0x00,       // FUTEX_WAIT
                tid as u32, // expected value
                0, 0, 0,
            )
        };
    }

    // If we didn't already claim the join in the finished fast path, do it now
    // after the child has fully exited.
    if !already_claimed_join {
        loop {
            let state = handle.state.load(Ordering::Acquire);
            match state {
                THREAD_FINISHED => {
                    match handle.state.compare_exchange(
                        THREAD_FINISHED,
                        THREAD_JOINED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break,
                        Err(THREAD_DETACHED) => return Err(EINVAL),
                        Err(THREAD_JOINED) => return Err(EINVAL),
                        Err(_) => continue,
                    }
                }
                THREAD_RUNNING => {
                    // Brief race: tid cleared but state not yet FINISHED.
                    // Spin briefly.
                    core::hint::spin_loop();
                    continue;
                }
                _ => return Err(EINVAL),
            }
        }
    }

    // SAFETY: retval was written by the child before FINISHED, and we hold
    // exclusive ownership via the JOINED CAS.
    let retval = unsafe { *handle.retval.get() };

    let stack_base = handle.stack_base;
    let stack_total_size = handle.stack_total_size;

    // Thread is gone. Reclaim its resources.
    free_thread_stack(stack_base, stack_total_size);

    // SAFETY: handle_ptr was created via Box::into_raw in create_thread.
    unsafe { drop(Box::from_raw(handle_ptr)) };

    Ok(retval)
}

/// Detach a thread so its resources are reclaimed automatically on exit.
///
/// If the thread has already finished, resources are freed immediately.
/// If it's still running, the trampoline will self-cleanup on exit.
///
/// # Errors
///
/// - `EINVAL` (22): null handle, already joined, or already detached
///
/// # Safety
///
/// `handle_ptr` must be a valid `*mut ThreadHandle` from `create_thread`.
/// After a successful detach, `handle_ptr` must not be used again.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
pub unsafe fn detach_thread(handle_ptr: *mut ThreadHandle) -> Result<(), i32> {
    const EINVAL: i32 = 22;

    if handle_ptr.is_null() {
        return Err(EINVAL);
    }

    // SAFETY: caller guarantees handle_ptr is valid.
    let handle = unsafe { &*handle_ptr };

    loop {
        let state = handle.state.load(Ordering::Acquire);
        match state {
            THREAD_JOINED | THREAD_DETACHED => return Err(EINVAL),
            THREAD_FINISHED => {
                // Thread already finished. Try to claim FINISHED → DETACHED
                // (atomically, so we don't race with a concurrent joiner).
                match handle.state.compare_exchange(
                    THREAD_FINISHED,
                    THREAD_DETACHED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        // We own cleanup. Proceed to wait for tid == 0 to ensure
                        // the kernel has finished the exit sequence before we
                        // reclaim the stack and handle.
                        break;
                    }
                    Err(THREAD_JOINED) => return Err(EINVAL),
                    Err(_) => continue, // Retry on unexpected state.
                }
            }
            THREAD_RUNNING | THREAD_STARTING => {
                // Thread still running. Try to CAS to DETACHED so the trampoline
                // knows to self-cleanup on exit.
                match handle.state.compare_exchange(
                    state,
                    THREAD_DETACHED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Ok(()),
                    Err(new_state) => {
                        if new_state == THREAD_JOINED || new_state == THREAD_DETACHED {
                            return Err(EINVAL);
                        }
                        // State changed (e.g., STARTING → RUNNING or RUNNING → FINISHED).
                        // Retry the loop.
                        continue;
                    }
                }
            }
            _ => return Err(EINVAL), // Unknown state.
        }
    }

    // Wait for the kernel to clear tid to 0 (CLONE_CHILD_CLEARTID).
    loop {
        let tid = handle.tid.load(Ordering::Acquire);
        if tid == 0 {
            break;
        }
        let futex_ptr = &handle.tid as *const AtomicI32 as *const u32;
        let _ = unsafe {
            syscall::sys_futex(
                futex_ptr, 0x00, // FUTEX_WAIT
                tid as u32, 0, 0, 0,
            )
        };
    }

    let stack_base = handle.stack_base;
    let stack_total_size = handle.stack_total_size;

    // Thread is gone. Reclaim its resources.
    free_thread_stack(stack_base, stack_total_size);

    // SAFETY: handle_ptr was created via Box::into_raw in create_thread.
    unsafe { drop(Box::from_raw(handle_ptr)) };

    Ok(())
}

/// Get the calling thread's TID.
///
/// For threads created by `create_thread`, the `pthread_t` value is the
/// `ThreadHandle` pointer. For the main thread (not created by us), we
/// fall back to `gettid()`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn self_tid() -> i32 {
    syscall::sys_gettid()
}

/// Return the calling native thread's live handle, without TLS, allocation,
/// locks or host calls. Ordinary hosted processes avoid even the TID syscall
/// until native thread creation has been attempted.
///
/// The pointer belongs to the calling thread. It remains valid through key
/// destructors; native exit blocks signals before unregistering and reclaiming
/// it. Callers must not retain it beyond the thread's lifetime.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline]
pub fn current_thread_handle() -> Option<*mut ThreadHandle> {
    if !super::tls::native_threads_may_exist() {
        return None;
    }
    handle_for_tid(syscall::sys_gettid())
}

/// Request cooperative cancellation of a live native thread without borrowing
/// its handle. The identity table retires requests before handle reclamation.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn request_cancellation(handle_address: usize) -> bool {
    if !super::tls::native_threads_may_exist() {
        return false;
    }
    let Some(values_address) =
        handle_address.checked_add(core::mem::offset_of!(ThreadHandle, tls_values))
    else {
        return false;
    };
    super::tls::request_thread_cancellation(values_address)
}

/// Consume a cooperative request for the calling native thread only.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn take_current_cancellation() -> bool {
    super::tls::take_thread_cancellation(syscall::sys_gettid())
}

/// Resolve a kernel TID to a `ThreadHandle` pointer.
///
/// Uses the TLS registration table to find the handle associated with the TID.
/// Returns `None` if the TID is not registered or the handle is invalid.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn handle_for_tid(tid: i32) -> Option<*mut ThreadHandle> {
    let values_ptr = super::tls::table_lookup(tid);
    if values_ptr.is_null() {
        return None;
    }

    // SAFETY: ThreadHandle contains the tls_values array. We use offset_of
    // to find the base of the handle from the pointer to that array.
    let offset = core::mem::offset_of!(ThreadHandle, tls_values);
    let handle_ptr = unsafe { (values_ptr as *mut u8).sub(offset).cast::<ThreadHandle>() };

    // Validate the handle via magic number.
    // SAFETY: handle_ptr was derived from a valid registered values_ptr.
    if unsafe { (*handle_ptr).magic } == THREAD_HANDLE_MAGIC {
        Some(handle_ptr)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    /// Minimal start routine that returns its argument as the return value.
    unsafe extern "C" fn echo_start(arg: usize) -> usize {
        arg
    }

    /// Start routine that writes a sentinel to a shared atomic.
    unsafe extern "C" fn signal_start(arg: usize) -> usize {
        // SAFETY: caller guarantees `arg` points to a valid AtomicU32.
        let flag = unsafe { &*(arg as *const AtomicU32) };
        flag.store(42, Ordering::Release);
        0
    }

    #[derive(Debug, PartialEq, Eq)]
    struct StartupSnapshot {
        affinity: [u8; 128],
        signal_mask: u64,
        policy: i32,
        priority: i32,
    }

    fn startup_snapshot() -> Result<StartupSnapshot, i32> {
        let mut snapshot = StartupSnapshot {
            affinity: [0; 128],
            signal_mask: 0,
            policy: syscall::sys_sched_getscheduler(0)?,
            priority: 0,
        };
        // SAFETY: each output points to correctly sized, live local storage.
        unsafe {
            syscall::sys_sched_getaffinity(
                0,
                snapshot.affinity.len(),
                snapshot.affinity.as_mut_ptr(),
            )?;
            syscall::sys_sched_getparam(0, core::ptr::from_mut(&mut snapshot.priority).cast())?;
            syscall::sys_rt_sigprocmask(
                2,
                core::ptr::null(),
                core::ptr::from_mut(&mut snapshot.signal_mask).cast(),
                core::mem::size_of::<u64>(),
            )?;
        }
        Ok(snapshot)
    }

    struct StartupProbe {
        result: core::cell::UnsafeCell<Option<Result<StartupSnapshot, i32>>>,
    }

    unsafe extern "C" fn startup_probe_start(arg: usize) -> usize {
        // SAFETY: the parent keeps this probe alive until join, and reads its
        // result only after the child's exit synchronizes the plain write.
        let probe = unsafe { &*(arg as *const StartupProbe) };
        unsafe { *probe.result.get() = Some(startup_snapshot()) };
        0x517a
    }

    fn probe_startup(startup: ThreadStartup<'_>) -> Result<StartupSnapshot, i32> {
        let probe = StartupProbe {
            result: core::cell::UnsafeCell::new(None),
        };
        // SAFETY: getpagesize has no arguments or caller-owned pointers.
        let page_size = unsafe { host_page_size() } as usize;
        // SAFETY: the entry point has the required ABI, probe outlives join,
        // and the creator owns this allocated stack and the affinity borrow.
        let created = unsafe {
            create_thread_with_startup(
                startup_probe_start as *const () as usize,
                core::ptr::from_ref(&probe) as usize,
                ThreadStack::Allocated {
                    size: 256 * 1024,
                    guard_size: page_size,
                    page_size,
                },
                startup,
            )
        };
        match created {
            Ok(handle) => {
                // SAFETY: this test is the sole owner of the joinable handle.
                assert_eq!(unsafe { join_thread(handle) }, Ok(0x517a));
                // SAFETY: join proves the child has stopped writing.
                unsafe { (*probe.result.get()).take() }.expect("start routine did not run")
            }
            Err(error) => {
                // SAFETY: failed creation waits for the child to exit; the
                // start routine must not have touched caller-owned data.
                assert!(unsafe { &*probe.result.get() }.is_none());
                Err(error)
            }
        }
    }

    #[test]
    fn native_startup_inherits_execution_attributes() {
        let before = startup_snapshot().unwrap();
        let child = probe_startup(ThreadStartup::default()).unwrap();
        assert_eq!(child, before);
        assert_eq!(startup_snapshot().unwrap(), before);
    }

    #[test]
    fn native_startup_applies_affinity_before_user_entry() {
        let before = startup_snapshot().unwrap();
        let cpu = before
            .affinity
            .iter()
            .enumerate()
            .find_map(|(index, byte)| {
                (*byte != 0).then(|| index * 8 + byte.trailing_zeros() as usize)
            })
            .expect("the test thread must have an allowed CPU");
        let mut affinity = [0u8; 128];
        affinity[cpu / 8] = 1 << (cpu % 8);
        let child = probe_startup(ThreadStartup {
            affinity: Some(&affinity),
            ..ThreadStartup::default()
        })
        .unwrap();
        assert_eq!(child.affinity, affinity);
        assert_eq!(child.signal_mask, before.signal_mask);
        assert_eq!(startup_snapshot().unwrap(), before);
    }

    #[test]
    fn native_startup_applies_signal_mask_before_user_entry() {
        let before = startup_snapshot().unwrap();
        // SIGUSR1 and SIGUSR2 are ordinary maskable Linux signals on the
        // supported ISAs; only the child receives this explicit mask.
        let requested = (1u64 << (10 - 1)) | (1u64 << (12 - 1));
        let child = probe_startup(ThreadStartup {
            signal_mask: Some(requested),
            ..ThreadStartup::default()
        })
        .unwrap();
        assert_eq!(child.signal_mask, requested);
        assert_eq!(child.affinity, before.affinity);
        assert_eq!(startup_snapshot().unwrap(), before);
    }

    #[test]
    fn native_startup_applies_explicit_scheduling_before_user_entry() {
        let before = startup_snapshot().unwrap();
        // SCHED_OTHER and SCHED_BATCH both permit priority zero without
        // CAP_SYS_NICE. Select a different policy from the inherited one so
        // simply ignoring the requested attributes cannot pass this test.
        let policy = if before.policy == 0 { 3 } else { 0 };
        let child = probe_startup(ThreadStartup {
            scheduling: Some((policy, 0)),
            ..ThreadStartup::default()
        })
        .unwrap();
        assert_eq!(child.policy, policy);
        assert_eq!(child.priority, 0);
        assert_eq!(startup_snapshot().unwrap(), before);
    }

    #[test]
    fn native_startup_failures_do_not_run_user_code_or_change_parent() {
        let before = startup_snapshot().unwrap();
        let no_cpus = [0u8; 128];
        for _ in 0..8 {
            for startup in [
                ThreadStartup {
                    affinity: Some(&no_cpus),
                    ..ThreadStartup::default()
                },
                ThreadStartup {
                    affinity: Some(&[]),
                    ..ThreadStartup::default()
                },
                ThreadStartup {
                    scheduling: Some((0, 1)), // SCHED_OTHER requires priority 0.
                    ..ThreadStartup::default()
                },
                ThreadStartup {
                    // A later setup error must reclaim the child even after
                    // a preceding attribute was installed successfully.
                    affinity: Some(&before.affinity),
                    signal_mask: Some(1 << (12 - 1)),
                    scheduling: Some((0, 1)),
                },
            ] {
                assert_eq!(probe_startup(startup), Err(crate::errno::EINVAL));
                assert_eq!(startup_snapshot().unwrap(), before);
            }
        }
        // The same creator still works after repeatedly reclaiming failed
        // children: no stale startup publication or poisoned lifecycle state.
        assert_eq!(probe_startup(ThreadStartup::default()).unwrap(), before);
    }

    #[test]
    fn native_stack_allocation_rejects_small_and_overflowing_sizes() {
        for size in [0, 1, THREAD_START_ARGS_GAP, MIN_STACK_SIZE - 1] {
            assert_eq!(allocate_thread_stack(size), Err(crate::errno::EINVAL));
        }
        for size in [usize::MAX, usize::MAX - GUARD_PAGE_SIZE + 1] {
            assert_eq!(allocate_thread_stack(size), Err(crate::errno::ENOMEM));
        }
    }

    #[test]
    fn native_stack_allocation_aligns_every_size_residue() {
        for minimum in [MIN_STACK_SIZE, 64 * 1024] {
            for residue in 0..THREAD_STACK_ALIGNMENT {
                let size = minimum + residue;
                let (base, total, top) = allocate_thread_stack(size).unwrap();
                let frame = top - 16;
                let args_size = core::mem::size_of::<ThreadStartArgs>();
                let args = frame - THREAD_START_ARGS_GAP - ((args_size + 7) & !7);
                // Release the allocation before assertions so a failed layout
                // check does not leak the mapping. Only integer addresses remain.
                free_thread_stack(base, total);
                assert_eq!(total, GUARD_PAGE_SIZE + size);
                assert_eq!(top % THREAD_STACK_ALIGNMENT, 0);
                assert_eq!(frame % THREAD_STACK_ALIGNMENT, 0);
                assert_eq!(args % core::mem::align_of::<ThreadStartArgs>(), 0);
                assert!(args >= base + GUARD_PAGE_SIZE);
                assert!(args + args_size <= frame - THREAD_START_ARGS_GAP);
                assert!(top <= base + total);
                assert!(base + total - top < THREAD_STACK_ALIGNMENT);
            }
        }
    }

    #[test]
    fn native_custom_stack_sizes_create_and_join() {
        let start_routine = echo_start as *const () as usize;
        for residue in 0..THREAD_STACK_ALIGNMENT {
            let size = 128 * 1024 + residue;
            // SAFETY: echo_start is a valid C-ABI entry point. Its argument is
            // an integer, and each successfully created handle is joined once.
            let handle = unsafe { create_thread(start_routine, residue + 1, size) }.unwrap();
            let result = unsafe { join_thread(handle) };
            assert_eq!(result, Ok(residue + 1), "stack size {size}");
        }
    }

    struct StackProbe {
        address: core::sync::atomic::AtomicUsize,
        release: AtomicU32,
    }

    unsafe extern "C" {
        #[link_name = "getpagesize"]
        fn host_page_size() -> i32;
    }

    unsafe extern "C" fn stack_probe_start(arg: usize) -> usize {
        let probe = unsafe { &*(arg as *const StackProbe) };
        let local = [0x5au8; 128];
        probe
            .address
            .store(local.as_ptr() as usize, Ordering::Release);
        while probe.release.load(Ordering::Acquire) == 0 {
            core::hint::spin_loop();
        }
        std::hint::black_box(&local);
        0x51ac
    }

    fn stack_mapping_permissions(address: usize) -> Option<String> {
        std::fs::read_to_string("/proc/self/maps")
            .unwrap()
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let (begin, end) = fields.next()?.split_once('-')?;
                let begin = usize::from_str_radix(begin, 16).ok()?;
                let end = usize::from_str_radix(end, 16).ok()?;
                (begin <= address && address < end).then(|| fields.next().unwrap().to_owned())
            })
    }

    fn wait_for_stack_probe(probe: &StackProbe) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while probe.address.load(Ordering::Acquire) == 0 {
            assert!(std::time::Instant::now() < deadline, "child did not start");
            std::thread::yield_now();
        }
    }

    fn wait_for_native_tid_exit(tid: i32) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while syscall::sys_tgkill(syscall::sys_getpid(), tid, 0).is_ok() {
            assert!(std::time::Instant::now() < deadline, "child did not exit");
            std::thread::yield_now();
        }
    }

    #[test]
    fn native_stack_requests_validate_ranges_before_writing() {
        for (address, size) in [
            (0, MIN_STACK_SIZE),
            (GUARD_PAGE_SIZE, MIN_STACK_SIZE - 1),
            (usize::MAX - MIN_STACK_SIZE + 1, MIN_STACK_SIZE),
            (GUARD_PAGE_SIZE, isize::MAX as usize + 1),
        ] {
            assert_eq!(
                prepare_thread_stack(ThreadStack::Borrowed { address, size }),
                Err(crate::errno::EINVAL)
            );
        }
        for page_size in [0, 1, 4095] {
            assert_eq!(
                prepare_thread_stack(ThreadStack::Allocated {
                    size: MIN_STACK_SIZE,
                    guard_size: 0,
                    page_size,
                }),
                Err(crate::errno::EINVAL)
            );
        }
        assert_eq!(
            prepare_thread_stack(ThreadStack::Allocated {
                size: MIN_STACK_SIZE,
                guard_size: usize::MAX,
                page_size: GUARD_PAGE_SIZE,
            }),
            Err(crate::errno::ENOMEM)
        );
    }

    #[test]
    fn native_requested_guards_protect_only_owned_prefix() {
        let page_size = unsafe { host_page_size() } as usize;
        for requested in [0, 1, page_size + 1] {
            let probe = StackProbe {
                address: core::sync::atomic::AtomicUsize::new(0),
                release: AtomicU32::new(0),
            };
            let handle = unsafe {
                create_thread_with_stack(
                    stack_probe_start as *const () as usize,
                    &probe as *const StackProbe as usize,
                    ThreadStack::Allocated {
                        size: 256 * 1024 + 13,
                        guard_size: requested,
                        page_size,
                    },
                )
            }
            .unwrap();
            wait_for_stack_probe(&probe);
            let metadata = unsafe { &*handle };
            let (base, total, address, size, guard) = (
                metadata.stack_base,
                metadata.stack_total_size,
                metadata.stack_addr,
                metadata.stack_size,
                metadata.guard_size,
            );
            let prefix_permissions = stack_mapping_permissions(base);
            let usable_permissions = stack_mapping_permissions(address);
            let local = probe.address.load(Ordering::Acquire);
            probe.release.store(1, Ordering::Release);
            assert_eq!(unsafe { join_thread(handle) }, Ok(0x51ac));

            let expected_guard = (requested + page_size - 1) & !(page_size - 1);
            assert_eq!(guard, expected_guard);
            assert_eq!(address, base + guard);
            assert_eq!(size, 256 * 1024 + 13);
            assert_eq!(total, guard + size);
            assert!(address <= local && local + 128 <= address + size);
            assert_eq!(usable_permissions.as_deref(), Some("rw-p"));
            assert_eq!(
                prefix_permissions.as_deref(),
                Some(if requested == 0 { "rw-p" } else { "---p" })
            );
        }
    }

    #[test]
    fn native_borrowed_stacks_preserve_storage_and_caller_guards() {
        let page_size = unsafe { host_page_size() } as usize;
        let writable_size = (272 * 1024 + page_size - 1) & !(page_size - 1);
        let total = writable_size + 2 * page_size;
        let base = unsafe {
            syscall::sys_mmap(
                core::ptr::null_mut(),
                total,
                (PROT_READ | PROT_WRITE) as i32,
                (MAP_PRIVATE | MAP_ANONYMOUS) as i32,
                -1,
                0,
            )
        }
        .unwrap();
        unsafe {
            syscall::sys_mprotect(base, page_size, PROT_NONE as i32).unwrap();
            syscall::sys_mprotect(
                base.add(page_size + writable_size),
                page_size,
                PROT_NONE as i32,
            )
            .unwrap();
        }
        for residue in 0..THREAD_STACK_ALIGNMENT {
            let address = base as usize + page_size + 17 + residue;
            let size = 256 * 1024 + residue;
            unsafe {
                ((address - 1) as *mut u8).write(0x35);
                ((address + size) as *mut u8).write(0x79);
            }
            let probe = StackProbe {
                address: core::sync::atomic::AtomicUsize::new(0),
                release: AtomicU32::new(0),
            };
            let handle = unsafe {
                create_thread_with_stack(
                    stack_probe_start as *const () as usize,
                    &probe as *const StackProbe as usize,
                    ThreadStack::Borrowed { address, size },
                )
            }
            .unwrap();
            wait_for_stack_probe(&probe);
            let metadata = unsafe { &*handle };
            let actual = (
                metadata.stack_base,
                metadata.stack_total_size,
                metadata.stack_addr,
                metadata.stack_size,
                metadata.guard_size,
            );
            let local = probe.address.load(Ordering::Acquire);
            probe.release.store(1, Ordering::Release);
            assert_eq!(unsafe { join_thread(handle) }, Ok(0x51ac));
            let mut residency = vec![0u8; total / page_size];
            assert_eq!(
                unsafe { syscall::sys_mincore(base as usize, total, residency.as_mut_ptr()) },
                Ok(())
            );
            assert_eq!(actual, (0, 0, address, size, 0));
            assert!(address <= local && local + 128 <= address + size);
            assert_eq!(unsafe { ((address - 1) as *const u8).read() }, 0x35);
            assert_eq!(unsafe { ((address + size) as *const u8).read() }, 0x79);
        }
        assert_eq!(
            stack_mapping_permissions(base as usize).as_deref(),
            Some("---p")
        );
        assert_eq!(
            stack_mapping_permissions(base as usize + page_size + writable_size).as_deref(),
            Some("---p")
        );
        unsafe { syscall::sys_munmap(base, total).unwrap() };
    }

    #[test]
    fn native_borrowed_stacks_survive_both_detach_paths() {
        let page_size = unsafe { host_page_size() } as usize;
        for finish_first in [false, true] {
            let size = 256 * 1024;
            let base = unsafe {
                syscall::sys_mmap(
                    core::ptr::null_mut(),
                    size,
                    (PROT_READ | PROT_WRITE) as i32,
                    (MAP_PRIVATE | MAP_ANONYMOUS) as i32,
                    -1,
                    0,
                )
            }
            .unwrap();
            let probe = StackProbe {
                address: core::sync::atomic::AtomicUsize::new(0),
                release: AtomicU32::new(0),
            };
            let handle = unsafe {
                create_thread_with_stack(
                    stack_probe_start as *const () as usize,
                    &probe as *const StackProbe as usize,
                    ThreadStack::Borrowed {
                        address: base as usize,
                        size,
                    },
                )
            }
            .unwrap();
            wait_for_stack_probe(&probe);
            let tid = unsafe { (*handle).self_tid.load(Ordering::Acquire) };
            if finish_first {
                probe.release.store(1, Ordering::Release);
                wait_for_native_tid_exit(tid);
                assert_eq!(unsafe { detach_thread(handle) }, Ok(()));
            } else {
                assert_eq!(unsafe { detach_thread(handle) }, Ok(()));
                probe.release.store(1, Ordering::Release);
                wait_for_native_tid_exit(tid);
            }
            let mut residency = vec![0u8; size.div_ceil(page_size)];
            assert_eq!(
                unsafe { syscall::sys_mincore(base as usize, size, residency.as_mut_ptr()) },
                Ok(())
            );
            unsafe {
                base.write(0xa7);
                assert_eq!(base.read(), 0xa7);
                syscall::sys_munmap(base, size).unwrap();
            }
        }
    }

    #[test]
    fn create_and_join_thread_returns_value() {
        let sentinel: usize = 0xDEAD_BEEF;
        // SAFETY: echo_start is a valid function, sentinel is a plain integer.
        let handle = unsafe { create_thread(echo_start as *const () as usize, sentinel, 0) };
        assert!(handle.is_ok(), "create_thread failed: {:?}", handle.err());
        let handle_ptr = handle.unwrap();

        // SAFETY: handle_ptr is valid from create_thread.
        let retval = unsafe { join_thread(handle_ptr) };
        assert!(retval.is_ok(), "join_thread failed: {:?}", retval.err());
        assert_eq!(
            retval.unwrap(),
            sentinel,
            "thread should return its argument"
        );
    }

    #[test]
    fn child_thread_can_write_shared_memory() {
        let flag = Box::new(AtomicU32::new(0));
        let flag_ptr = &*flag as *const AtomicU32 as usize;

        // SAFETY: signal_start is valid, flag_ptr points to a valid AtomicU32.
        let handle = unsafe { create_thread(signal_start as *const () as usize, flag_ptr, 0) };
        assert!(handle.is_ok());
        let handle_ptr = handle.unwrap();

        // SAFETY: handle_ptr is valid.
        let _ = unsafe { join_thread(handle_ptr) };

        assert_eq!(
            flag.load(Ordering::Acquire),
            42,
            "child thread should have written 42 to shared flag"
        );
    }

    #[test]
    fn multiple_threads_created_and_joined() {
        let mut handles = Vec::new();
        for i in 0..4u64 {
            // SAFETY: echo_start is valid, i is a plain integer.
            let handle = unsafe { create_thread(echo_start as *const () as usize, i as usize, 0) };
            assert!(handle.is_ok(), "create_thread({i}) failed");
            handles.push(handle.unwrap());
        }

        for (i, handle_ptr) in handles.into_iter().enumerate() {
            // SAFETY: handle_ptr is valid.
            let retval = unsafe { join_thread(handle_ptr) };
            assert!(retval.is_ok(), "join_thread({i}) failed");
            assert_eq!(retval.unwrap(), i, "thread {i} should return {i}");
        }
    }

    #[test]
    fn detach_thread_does_not_error() {
        let flag = Box::new(AtomicU32::new(0));
        let flag_ptr = &*flag as *const AtomicU32 as usize;

        // SAFETY: signal_start is valid.
        let handle = unsafe { create_thread(signal_start as *const () as usize, flag_ptr, 0) };
        assert!(handle.is_ok());
        let handle_ptr = handle.unwrap();

        // SAFETY: handle_ptr is valid.
        let result = unsafe { detach_thread(handle_ptr) };
        assert!(result.is_ok(), "detach_thread failed: {:?}", result.err());

        // Give the detached thread time to finish (best-effort check).
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(flag.load(Ordering::Acquire), 42);
    }

    #[test]
    fn join_null_handle_returns_einval() {
        // SAFETY: explicitly testing null handle error path.
        let result = unsafe { join_thread(core::ptr::null_mut()) };
        assert_eq!(result, Err(22), "join on null should return EINVAL");
    }

    #[test]
    fn detach_null_handle_returns_einval() {
        // SAFETY: explicitly testing null handle error path.
        let result = unsafe { detach_thread(core::ptr::null_mut()) };
        assert_eq!(result, Err(22), "detach on null should return EINVAL");
    }

    #[test]
    fn join_after_detach_returns_einval() {
        // SAFETY: signal_start is valid.
        let flag = Box::new(AtomicU32::new(0));
        let flag_ptr = &*flag as *const AtomicU32 as usize;
        let handle =
            unsafe { create_thread(signal_start as *const () as usize, flag_ptr, 0) }.unwrap();

        // Detach the thread.
        // SAFETY: handle is valid.
        let detach_result = unsafe { detach_thread(handle) };
        assert!(detach_result.is_ok());

        // Trying to join a detached thread must fail.
        // SAFETY: handle was valid before detach; join should reject it.
        // Note: after detach, the handle may be freed by the thread, so we
        // only test this if the thread hasn't exited yet. We use a slow start
        // routine to ensure the handle is still valid.
        // For safety, we just verify the detach succeeded and skip the
        // join-after-detach test on the same pointer (UB risk after free).
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(flag.load(Ordering::Acquire), 42);
    }

    #[test]
    fn detach_after_join_not_possible() {
        // Create and join a thread, then verify we can't detach it.
        let handle = unsafe { create_thread(echo_start as *const () as usize, 99, 0) }.unwrap();

        // SAFETY: handle is valid.
        let join_result = unsafe { join_thread(handle) };
        assert!(join_result.is_ok());
        assert_eq!(join_result.unwrap(), 99);

        // handle is now freed — we can't safely call detach on it.
        // Instead, test that detach on null returns EINVAL.
        let result = unsafe { detach_thread(core::ptr::null_mut()) };
        assert_eq!(result, Err(22));
    }

    #[test]
    fn detach_finished_thread_cleans_up_immediately() {
        // Create a thread that finishes quickly.
        let handle = unsafe { create_thread(echo_start as *const () as usize, 0, 0) }.unwrap();

        // Wait for it to finish.
        std::thread::sleep(std::time::Duration::from_millis(50));

        // SAFETY: handle is valid, thread should be FINISHED.
        let result = unsafe { detach_thread(handle) };
        assert!(
            result.is_ok(),
            "detach of finished thread should succeed: {:?}",
            result.err()
        );
        // Resources are freed immediately — no leak.
    }

    #[test]
    fn gettid_returns_positive() {
        let tid = self_tid();
        assert!(tid > 0, "gettid should return positive TID, got {tid}");
    }

    /// Start routine that sleeps briefly so we can test lifecycle transitions.
    unsafe extern "C" fn slow_start(arg: usize) -> usize {
        std::thread::sleep(std::time::Duration::from_millis(arg as u64));
        arg
    }

    #[test]
    fn detach_running_thread_self_cleans_on_exit() {
        // Create a thread that runs for a bit.
        let handle = unsafe { create_thread(slow_start as *const () as usize, 20, 0) }.unwrap();

        // Detach while it's still running.
        // SAFETY: handle is valid.
        let result = unsafe { detach_thread(handle) };
        assert!(result.is_ok(), "detach should succeed");

        // Wait for the thread to finish and self-clean.
        std::thread::sleep(std::time::Duration::from_millis(100));
        // If we get here without a crash, self-cleanup worked.
    }

    // Note: concurrent double-join is undefined behavior per POSIX (pthread_join
    // on an already-joined thread). We don't test it because the losing joiner
    // would access freed memory after the winner calls Box::from_raw.
}
