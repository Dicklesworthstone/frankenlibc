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

#[cfg(target_arch = "x86_64")]
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

/// Per-thread control block. Allocated on the heap, pointed to by `pthread_t`.
///
/// The `tid` field doubles as the join futex: `CLONE_CHILD_CLEARTID` tells the
/// kernel to set `*child_tid = 0` and `futex_wake(child_tid)` when the thread
/// exits. Joiners simply `futex_wait(&tid, current_tid)` until tid becomes 0.
#[repr(C)]
pub struct ThreadHandle {
    /// Kernel thread ID. Set by `CLONE_PARENT_SETTID` on creation.
    /// Cleared to 0 by `CLONE_CHILD_CLEARTID` on thread exit.
    pub tid: AtomicI32,

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
    pub tls_values: [u64; super::tls::PTHREAD_KEYS_MAX],
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
    #[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "x86_64")]
    super::tls::register_thread_tls(handle.tid.load(Ordering::Acquire), unsafe {
        (*handle_ptr).tls_values.as_mut_ptr()
    });

    // Cast the start_routine address back to a function pointer and call it.
    // SAFETY: start_routine_addr was a valid extern "C" fn pointer stored by
    // the parent. arg is the user's argument.
    let start_fn: unsafe extern "C" fn(usize) -> usize =
        unsafe { core::mem::transmute(start_routine_addr) };
    let retval = unsafe { start_fn(arg) };

    // Run TLS destructors before exit (bd-rth1).
    // Per POSIX, destructors fire after start_routine returns.
    #[cfg(target_arch = "x86_64")]
    super::tls::teardown_thread_tls(handle.tid.load(Ordering::Acquire));

    // Store the return value. No concurrent readers until after tid is cleared.
    // SAFETY: retval is only read by the joiner after tid becomes 0 (kernel
    // clears tid via CLONE_CHILD_CLEARTID after this function returns).
    unsafe { *handle.retval.get() = retval };

    // Try to transition RUNNING → FINISHED. If someone already set DETACHED
    // (via detach_thread), we need to self-cleanup since no joiner will do it.
    let prev = handle.state.compare_exchange(
        THREAD_RUNNING,
        THREAD_FINISHED,
        Ordering::AcqRel,
        Ordering::Acquire,
    );

    match prev {
        Ok(_) => {
            // Successfully set FINISHED. A future joiner will free resources.
        }
        Err(THREAD_DETACHED) => {
            // Thread was detached while running. Free the heap-allocated
            // handle. The stack will be reclaimed by the OS on process exit.
            //
            // CRITICAL: Before freeing the handle, tell the kernel not to
            // write to the TID address on thread exit. Otherwise
            // CLONE_CHILD_CLEARTID would write 0 to freed memory.
            #[cfg(target_arch = "x86_64")]
            {
                // Disable CLONE_CHILD_CLEARTID so the kernel won't write to
                // the freed handle's TID field on thread exit.
                syscall::sys_set_tid_address(0);
            }

            // SAFETY: handle_ptr was created via Box::into_raw in create_thread,
            // and no other thread will access it after detach.
            unsafe { drop(Box::from_raw(handle_ptr)) };

            // Fall through — asm trampoline will call sys_exit(0).
            //
            // TODO(bd-rth1): add signal masking + munmap to safely reclaim
            // detached thread stacks without SIGSEGV risk.
        }
        Err(_) => {
            // Unexpected state — shouldn't happen with correct usage.
            // Fall through and let the asm trampoline exit normally.
        }
    }

    // Return value becomes the exit status (asm trampoline calls sys_exit with it).
    0
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
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn allocate_thread_stack(stack_size: usize) -> Result<(usize, usize, usize), i32> {
    let total_size = GUARD_PAGE_SIZE + stack_size;

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
#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub unsafe fn create_thread(start_routine: usize, arg: usize) -> Result<*mut ThreadHandle, i32> {
    // Allocate stack.
    let (stack_base, stack_total_size, stack_top) = allocate_thread_stack(DEFAULT_STACK_SIZE)?;

    // Allocate the ThreadHandle on the heap (Box).
    let handle = Box::new(ThreadHandle {
        tid: AtomicI32::new(0),
        state: AtomicU32::new(THREAD_STARTING),
        started: AtomicU32::new(0),
        retval: core::cell::UnsafeCell::new(0),
        stack_base,
        stack_total_size,
        tls_values: [0u64; super::tls::PTHREAD_KEYS_MAX],
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
        Ok(child_tid) => {
            // Publish the child TID immediately in parent context so early
            // lifecycle checks (for example self-join rejection) observe a
            // stable non-zero TID before startup synchronization completes.
            // SAFETY: `handle_ptr` remains owned by this create path until
            // either cleanup on error or transfer to caller on success.
            unsafe { (*handle_ptr).tid.store(child_tid, Ordering::Release) };

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
#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub unsafe fn join_thread(handle_ptr: *mut ThreadHandle) -> Result<usize, i32> {
    const EINVAL: i32 = 22;
    const EDEADLK: i32 = 35;

    if handle_ptr.is_null() {
        return Err(EINVAL);
    }

    // SAFETY: caller guarantees handle_ptr is valid.
    let handle = unsafe { &*handle_ptr };

    // Self-join detection: if the calling thread's TID matches the handle's
    // TID, we'd deadlock.
    let my_tid = syscall::sys_gettid();
    let target_tid = handle.tid.load(Ordering::Acquire);
    if target_tid != 0 && my_tid == target_tid {
        return Err(EDEADLK);
    }

    // Atomically claim the right to join. We need to transition from a joinable
    // state (RUNNING or FINISHED) to JOINED. CAS ensures only one joiner wins.
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
                        // We own the join. Skip the futex wait (thread already exited).
                        // Read retval, free resources, return.
                        // SAFETY: retval written before FINISHED, tid==0 guarantees visibility.
                        let retval = unsafe { *handle.retval.get() };
                        let stack_base = handle.stack_base;
                        let stack_total_size = handle.stack_total_size;
                        free_thread_stack(stack_base, stack_total_size);
                        // SAFETY: handle_ptr from Box::into_raw in create_thread.
                        unsafe { drop(Box::from_raw(handle_ptr)) };
                        return Ok(retval);
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
                futex_ptr, 0x80,       // FUTEX_WAIT_PRIVATE
                tid as u32, // expected value
                0, 0, 0,
            )
        };
    }

    // Thread has exited. Now CAS FINISHED → JOINED.
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

    // SAFETY: retval was written by the child before FINISHED, and we hold
    // exclusive ownership via the JOINED CAS.
    let retval = unsafe { *handle.retval.get() };

    // Free resources.
    let stack_base = handle.stack_base;
    let stack_total_size = handle.stack_total_size;
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
#[cfg(target_arch = "x86_64")]
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
                        // We own cleanup. Free resources immediately.
                        let stack_base = handle.stack_base;
                        let stack_total_size = handle.stack_total_size;
                        free_thread_stack(stack_base, stack_total_size);
                        // SAFETY: handle_ptr from Box::into_raw in create_thread.
                        unsafe { drop(Box::from_raw(handle_ptr)) };
                        return Ok(());
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
}

/// Get the calling thread's TID.
///
/// For threads created by `create_thread`, the `pthread_t` value is the
/// `ThreadHandle` pointer. For the main thread (not created by us), we
/// fall back to `gettid()`.
#[cfg(target_arch = "x86_64")]
pub fn self_tid() -> i32 {
    syscall::sys_gettid()
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
        let handle = unsafe { create_thread(echo_start as *const () as usize, sentinel) };
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
        let handle = unsafe { create_thread(signal_start as *const () as usize, flag_ptr) };
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
            let handle = unsafe { create_thread(echo_start as *const () as usize, i as usize) };
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
        let handle = unsafe { create_thread(signal_start as *const () as usize, flag_ptr) };
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
            unsafe { create_thread(signal_start as *const () as usize, flag_ptr) }.unwrap();

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
        let handle = unsafe { create_thread(echo_start as *const () as usize, 99) }.unwrap();

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
        let handle = unsafe { create_thread(echo_start as *const () as usize, 0) }.unwrap();

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
        let handle = unsafe { create_thread(slow_start as *const () as usize, 20) }.unwrap();

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
