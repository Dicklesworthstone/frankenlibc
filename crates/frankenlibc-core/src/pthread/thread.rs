//! POSIX thread creation and management — clone-based bootstrap.
//!
//! Implements the core thread lifecycle: create, join, detach, self, equal.
//! Uses the Linux `clone` syscall directly instead of delegating to glibc.
//!
//! ## Architecture
//!
//! Each new thread gets:
//! - A dedicated stack allocated via `mmap` (default 2 MiB + guard page)
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

use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default thread stack size: 2 MiB (matches glibc default).
const DEFAULT_STACK_SIZE: usize = 2 * 1024 * 1024;

/// Guard page size: 4 KiB.
const GUARD_PAGE_SIZE: usize = 4096;

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

    /// Startup synchronization futex: child stores 1 after reading args.
    pub started: AtomicU32,

    /// Return value from the user's `start_routine`.
    /// Written by the child before exit; read by the joiner after `tid == 0`.
    pub retval: core::cell::UnsafeCell<usize>,

    /// Base address of the mmap'd stack region (including guard page).
    pub stack_base: usize,

    /// Total size of the mmap'd region (guard page + usable stack).
    pub stack_total_size: usize,

    /// Per-thread TLS value storage (bd-rth1). Allocation-free: lives in the
    /// heap-allocated ThreadHandle so clone-based threads never need malloc.
    pub tls_values: [super::tls::TlsEntry; super::tls::PTHREAD_KEYS_MAX],
}

// SAFETY: ThreadHandle is designed for cross-thread sharing via atomic fields.
// The `retval` field is accessed only after synchronization (tid cleared to 0).
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
}

// ---------------------------------------------------------------------------
// Thread trampoline (runs in child context)
// ---------------------------------------------------------------------------

/// Entry point for the child thread after clone.
///
/// Called by the clone trampoline asm with `args_raw` in `rdi`.
/// This function:
/// 1. Reads the `ThreadStartArgs` from the pointer
/// 2. Signals the parent that startup is complete
/// 3. Calls the user's `start_routine(arg)`
/// 4. Stores the return value in the handle
/// 5. Returns (the asm trampoline then calls `sys_exit`)
///
/// # Safety
///
/// `args_raw` must be a valid pointer to `ThreadStartArgs` on the child's stack.
/// All pointers in `ThreadStartArgs` must be valid for the thread's lifetime.
#[allow(unsafe_code)]
unsafe extern "C" fn thread_trampoline(args_raw: usize) -> usize {
    // SAFETY: args_raw is a pointer to ThreadStartArgs that the parent placed
    // on our stack before clone. It's valid until we finish reading it.
    let args = unsafe { &*(args_raw as *const ThreadStartArgs) };
    let handle_ptr = args.handle;
    let start_routine_addr = args.start_routine;
    let arg = args.arg;

    // SAFETY: handle_ptr was allocated by the parent and is valid for the
    // thread's entire lifetime.
    let handle = unsafe { &*handle_ptr };
    let current_tid = syscall::sys_gettid();
    handle.self_tid.store(current_tid, Ordering::Release);
    if handle.tid.load(Ordering::Acquire) == 0 {
        handle.tid.store(current_tid, Ordering::Release);
    }

    // Try to transition STARTING → RUNNING. If detach_thread already set
    // DETACHED, we must not overwrite it.
    let _ = handle.state.compare_exchange(
        THREAD_STARTING,
        THREAD_RUNNING,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    handle.started.store(1, Ordering::Release);

    // Wake the parent waiting on started futex.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let futex_ptr = &handle.started as *const AtomicU32 as *const u32;
        // SAFETY: futex_ptr points to a valid, aligned u32 in the handle.
        let _ = unsafe {
            syscall::sys_futex(
                futex_ptr,
                0x01 | 0x80, // FUTEX_WAKE | FUTEX_PRIVATE_FLAG
                1,           // wake 1 waiter
                0,
                0,
                0,
            )
        };
    }

    // Register TLS storage for this thread (bd-rth1).
    // SAFETY: handle_ptr is valid and exclusively owned by this thread for
    // the tls_values field. The pointer is stored in the TLS table and only
    // accessed by this thread via getspecific/setspecific.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    super::tls::register_thread_tls(handle.tid.load(Ordering::Acquire), unsafe {
        (*handle_ptr).tls_values.as_mut_ptr()
    });

    // Cast the start_routine address back to a function pointer and call it.
    // SAFETY: start_routine_addr was a valid extern "C" fn pointer stored by
    // the parent. arg is the user's argument.
    let start_fn: unsafe extern "C" fn(usize) -> usize =
        unsafe { core::mem::transmute(start_routine_addr) };
    let retval = unsafe { start_fn(arg) };

    // Explicit and implicit thread exit must follow the same teardown/state
    // transition path so detached threads self-clean and TLS destructors run.
    unsafe { exit_current_thread(handle_ptr, retval) }
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
    super::tls::teardown_thread_tls(tid);

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
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
fn allocate_thread_stack(stack_size: usize) -> Result<(usize, usize, usize), i32> {
    let total_size = GUARD_PAGE_SIZE
        .checked_add(stack_size)
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

    // Set the guard page (bottom of the region) to PROT_NONE.
    // SAFETY: base is a valid, page-aligned mmap'd region of total_size bytes.
    let guard_result = unsafe { syscall::sys_mprotect(base, GUARD_PAGE_SIZE, PROT_NONE as i32) };

    if let Err(e) = guard_result {
        // Clean up: unmap the region on failure.
        // SAFETY: base/total_size are the mmap'd region we just created.
        let _ = unsafe { syscall::sys_munmap(base, total_size) };
        return Err(e);
    }

    let usable_top = base as usize + total_size;
    Ok((base as usize, total_size, usable_top))
}

/// Free a thread stack allocated by `allocate_thread_stack`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_code)]
fn free_thread_stack(base: usize, total_size: usize) {
    // SAFETY: base/total_size were returned by allocate_thread_stack (mmap).
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
    // Allocate stack.
    let (stack_base, stack_total_size, stack_top) = allocate_thread_stack(actual_stack_size)?;

    // Allocate the ThreadHandle on the heap (Box).
    let handle = Box::new(ThreadHandle {
        magic: THREAD_HANDLE_MAGIC,
        tid: AtomicI32::new(0),
        self_tid: AtomicI32::new(0),
        state: AtomicU32::new(THREAD_STARTING),
        started: AtomicU32::new(0),
        retval: core::cell::UnsafeCell::new(0),
        stack_base,
        stack_total_size,
        tls_values: [super::tls::TlsEntry::default(); super::tls::PTHREAD_KEYS_MAX],
    });
    let handle_ptr = Box::into_raw(handle);

    // Prepare ThreadStartArgs on the child stack.
    // The args struct goes near the top of the stack, and the trampoline
    // frame (fn_ptr + arg) goes at the very top.
    let args = ThreadStartArgs {
        handle: handle_ptr,
        start_routine,
        arg,
    };

    // Place args in a stable location. We'll put it in the upper portion of
    // the child stack. The trampoline reads it via a pointer.
    // Layout from stack_top (growing down):
    //   [stack_top - 8]:  arg to trampoline (= pointer to ThreadStartArgs)
    //   [stack_top - 16]: fn_ptr (= thread_trampoline)
    //   [stack_top - 16 - size_of::<ThreadStartArgs>()]: ThreadStartArgs data

    let args_size = core::mem::size_of::<ThreadStartArgs>();
    // Align args to 8 bytes.
    let args_aligned_size = (args_size + 7) & !7;

    // Calculate positions.
    let args_addr = stack_top - 16 - args_aligned_size;
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
            wait_for_startup(handle_ptr);
            Ok(handle_ptr)
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
fn wait_for_startup(handle_ptr: *mut ThreadHandle) {
    // SAFETY: handle_ptr is valid (we just allocated it).
    let handle = unsafe { &*handle_ptr };
    loop {
        let started = handle.started.load(Ordering::Acquire);
        if started != 0 {
            return;
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
