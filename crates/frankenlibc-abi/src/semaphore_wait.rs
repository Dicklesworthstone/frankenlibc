//! Semaphore ABI over one packed, glibc-compatible state word.
//!
//! Linux little-endian 64-bit sem_t stores tokens/waiters in the first eight
//! bytes and a sharing selector at offset eight. The selector is zero for
//! private storage and FUTEX_PRIVATE_FLAG for shared storage; its kernel flag
//! is the inverse. Runtime layout is verified against independently loaded
//! host entry points and separately exec'd processes, not a source translation.
use frankenlibc_core::pthread::semaphore::SemaphoreState;
use frankenlibc_core::syscall;
use std::ffi::{c_int, c_uint, c_void};

#[cfg(not(all(
    target_pointer_width = "64",
    target_endian = "little",
    target_has_atomic = "64"
)))]
compile_error!("the semaphore ABI requires little-endian 64-bit atomic storage");

#[inline(always)]
unsafe fn state(semaphore: *mut c_void) -> &'static SemaphoreState {
    // SAFETY: the ABI caller supplies a live initialized, eight-aligned sem_t.
    unsafe { &*semaphore.cast::<SemaphoreState>() }
}

#[inline(always)]
unsafe fn private_flag(semaphore: *mut c_void) -> c_int {
    // SAFETY: the immutable sharing selector lives at offset eight. Initialization
    // happens-before semaphore use; concurrent destruction/reinitialization is
    // outside the caller's contract. Read it before publishing/consuming a token.
    (unsafe { std::ptr::read(semaphore.cast::<u8>().add(8).cast::<c_int>()) })
        ^ libc::FUTEX_PRIVATE_FLAG
}

/// # Safety
/// semaphore is writable, eight-aligned Linux sem_t storage, not currently used.
pub(crate) unsafe fn init(semaphore: *mut c_void, shared: c_int, value: c_uint) -> c_int {
    let Some(initial) = SemaphoreState::new(value) else {
        unsafe { crate::errno_abi::set_abi_errno(libc::EINVAL) };
        return -1;
    };
    if semaphore.is_null() {
        unsafe { crate::errno_abi::set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // SAFETY: initialize the complete public storage before it is shared. The
    // packed atomic must never alias independently accessed 32-bit Rust atomics.
    unsafe {
        std::ptr::write(semaphore.cast::<SemaphoreState>(), initial);
        std::ptr::write_bytes(semaphore.cast::<u8>().add(8), 0, 24);
        std::ptr::write(
            semaphore.cast::<u8>().add(8).cast::<c_int>(),
            if shared == 0 {
                0
            } else {
                libc::FUTEX_PRIVATE_FLAG
            },
        );
    }
    0
}

/// # Safety
/// semaphore is initialized, with no blocked users. No owned resource exists
/// in the object; in particular, destruction need not overwrite waiter state.
pub(crate) unsafe fn destroy(semaphore: *mut c_void) -> c_int {
    if semaphore.is_null() {
        unsafe { crate::errno_abi::set_abi_errno(libc::EINVAL) };
        -1
    } else {
        0
    }
}

/// # Safety
/// semaphore is initialized and output points to writable int storage.
pub(crate) unsafe fn getvalue(semaphore: *mut c_void, output: *mut c_int) -> c_int {
    if semaphore.is_null() || output.is_null() {
        unsafe { crate::errno_abi::set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // SAFETY: preserve the complete atomic access width even while host users
    // change the packed waiter count. output remains caller-owned writable memory.
    unsafe { *output = state(semaphore).value() as c_int };
    0
}

/// # Safety
/// semaphore is initialized. This nonblocking operation is not a cancellation point.
pub(crate) unsafe fn trywait(semaphore: *mut c_void) -> c_int {
    if semaphore.is_null() {
        unsafe { crate::errno_abi::set_abi_errno(libc::EINVAL) };
        return -1;
    }
    if unsafe { state(semaphore) }.try_acquire() {
        0
    } else {
        unsafe { crate::errno_abi::set_abi_errno(libc::EAGAIN) };
        -1
    }
}

/// # Safety
/// semaphore is initialized. Signal-safe: only atomics, immutable metadata and
/// a raw wake are used. No memory access follows successful token publication.
pub unsafe extern "C" fn post(semaphore: *mut c_void) -> c_int {
    if semaphore.is_null() {
        unsafe { crate::errno_abi::set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // SAFETY: cache the selector while the caller must still own live storage.
    let private = unsafe { private_flag(semaphore) };
    let Some(wake) = unsafe { state(semaphore) }.post() else {
        unsafe { crate::errno_abi::set_abi_errno(libc::EOVERFLOW) };
        return -1;
    };
    // A last waiter may already have destroyed/unmapped the object. The packed
    // publication carries the wake decision, so do not load sem_t again here.
    if wake {
        // SAFETY: the kernel validates the address; an already unmapped word is
        // a harmless failed wake. No user-space dereference occurs after publish.
        let _ =
            unsafe { syscall::sys_futex(semaphore.cast(), libc::FUTEX_WAKE | private, 1, 0, 0, 0) };
    }
    0
}

#[inline(always)]
unsafe fn wait_common(
    semaphore: *mut c_void,
    deadline: Option<(c_int, &libc::timespec)>,
    mandatory_cancel: bool,
) -> c_int {
    if semaphore.is_null() {
        unsafe { crate::errno_abi::set_abi_errno(libc::EINVAL) };
        return -1;
    }
    if mandatory_cancel {
        // SAFETY: no state or guard exists yet. The inlined caller-origin rule
        // keeps internal libc operations noncanceling while honoring C callers.
        unsafe { crate::pthread_abi::at_cancellation_point(|| ()) };
    }
    // SAFETY: all metadata is read before a successful acquisition can release
    // the last reference to this storage. All state operations have one width.
    let private = unsafe { private_flag(semaphore) };
    let state = unsafe { state(semaphore) };
    if state.try_acquire() {
        return 0;
    }
    let Some(mut registration) = state.register() else {
        unsafe { crate::errno_abi::set_abi_errno(libc::EAGAIN) };
        return -1;
    };
    let expired = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let deadline =
        deadline.map(|(clock, time)| (clock, if time.tv_sec < 0 { &expired } else { time }));
    loop {
        // Consuming a token and unregistering are one atomic transition. Drop
        // is disarmed on success, but unregisters on timeout and forced unwind.
        if registration.try_acquire() {
            return 0;
        }
        let (operation, timeout, bitset) = match deadline {
            None => (libc::FUTEX_WAIT | private, 0, 0),
            Some((clock, time)) => (
                libc::FUTEX_WAIT_BITSET
                    | private
                    | if clock == libc::CLOCK_REALTIME {
                        libc::FUTEX_CLOCK_REALTIME
                    } else {
                        0
                    },
                time as *const libc::timespec as usize,
                u32::MAX,
            ),
        };
        // SAFETY: the kernel compares the low token word. Registration holds
        // the semaphore alive through the wait; C-unwind runs its cleanup.
        let result = unsafe {
            crate::pthread_abi::at_cancellation_point(|| {
                syscall::sys_futex(semaphore.cast(), operation, 0, timeout, 0, bitset)
            })
        };
        match result {
            Ok(_) | Err(libc::EAGAIN) => {}
            Err(error) => {
                unsafe { crate::errno_abi::set_abi_errno(error) };
                return -1;
            }
        }
    }
}

#[inline(always)]
pub(crate) unsafe fn wait_cp(semaphore: *mut c_void) -> c_int {
    unsafe { wait_common(semaphore, None, true) }
}

#[inline(always)]
pub(crate) unsafe fn timed_cp(
    semaphore: *mut c_void,
    clock: c_int,
    deadline: *const libc::timespec,
    mandatory_cancel: bool,
) -> c_int {
    if deadline.is_null() || (clock != libc::CLOCK_REALTIME && clock != libc::CLOCK_MONOTONIC) {
        unsafe { crate::errno_abi::set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // SAFETY: the caller provides a readable absolute timespec.
    let deadline = unsafe { &*deadline };
    if !(0..1_000_000_000).contains(&deadline.tv_nsec) {
        unsafe { crate::errno_abi::set_abi_errno(libc::EINVAL) };
        return -1;
    }
    unsafe { wait_common(semaphore, Some((clock, deadline)), mandatory_cancel) }
}

/// # Safety
/// Same public contract as sem_wait; cancellation may unwind into the caller.
pub unsafe extern "C-unwind" fn wait(semaphore: *mut c_void) -> c_int {
    unsafe { wait_cp(semaphore) }
}

/// # Safety
/// Same public contract as sem_timedwait, using an absolute realtime deadline.
pub unsafe extern "C-unwind" fn timedwait(
    semaphore: *mut c_void,
    deadline: *const libc::timespec,
) -> c_int {
    unsafe { timed_cp(semaphore, libc::CLOCK_REALTIME, deadline, true) }
}

/// # Safety
/// Same public contract as sem_clockwait, with the requested clock unchanged.
pub unsafe extern "C-unwind" fn clockwait(
    semaphore: *mut c_void,
    clock: c_int,
    deadline: *const libc::timespec,
) -> c_int {
    unsafe { timed_cp(semaphore, clock, deadline, false) }
}
