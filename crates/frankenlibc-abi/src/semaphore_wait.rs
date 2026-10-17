//! Shared semaphore acquisition and posting, for native plugins and C exports.
//!
//! Absolute deadlines retain their kernel clock. Waiter registration remains
//! live across cancellation, and an overflow never publishes an invalid value.
use frankenlibc_core::syscall;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

#[inline(always)]
unsafe fn word(semaphore: *mut c_void) -> &'static AtomicI32 {
    // SAFETY: callers provide aligned Linux sem_t storage of at least 32 bytes.
    unsafe { &*semaphore.cast::<AtomicI32>() }
}

#[inline(always)]
fn acquire(value: &AtomicI32) -> bool {
    let mut old = value.load(Ordering::SeqCst);
    while old > 0 {
        match value.compare_exchange_weak(old, old - 1, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(observed) => old = observed,
        }
    }
    false
}

/// # Safety
/// `semaphore` points to a live initialized sem_t. The operation is signal-safe:
/// it uses only atomics and a raw wake, never allocation or a process mutex.
pub unsafe extern "C" fn post(semaphore: *mut c_void) -> c_int {
    if semaphore.is_null() {
        unsafe { crate::errno_abi::set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let value = unsafe { word(semaphore) };
    let mut old = value.load(Ordering::Relaxed);
    loop {
        if old < 0 || old == i32::MAX {
            unsafe { crate::errno_abi::set_abi_errno(libc::EOVERFLOW) };
            return -1;
        }
        // SeqCst pairs with registration/recheck in the slow wait path. Do not
        // increment then undo on overflow: observers can see that invalid state.
        match value.compare_exchange_weak(old, old + 1, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => old = observed,
        }
    }
    let waiters = unsafe { &*semaphore.cast::<u8>().add(4).cast::<AtomicU32>() };
    if waiters.load(Ordering::SeqCst) != 0 {
        let _ = unsafe {
            syscall::sys_futex(
                semaphore.cast(),
                libc::FUTEX_WAKE | crate::unistd_abi::sem_futex_private_flag(semaphore),
                1,
                0,
                0,
                0,
            )
        };
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
        // A pending cancel must act before taking even an available token.
        // The existing caller-origin rule keeps libc-internal calls noncanceling.
        // No semaphore state or guard exists yet when this window opens.
        unsafe { crate::pthread_abi::at_cancellation_point(|| ()) };
    }
    let value = unsafe { word(semaphore) };
    if acquire(value) {
        return 0;
    }
    // Register before rechecking so a simultaneous post cannot miss our wake.
    let _registration = unsafe { crate::unistd_abi::sem_register_waiter(semaphore) };
    let expired = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let deadline =
        deadline.map(|(clock, time)| (clock, if time.tv_sec < 0 { &expired } else { time }));
    loop {
        if acquire(value) {
            return 0;
        }
        let private = crate::unistd_abi::sem_futex_private_flag(semaphore);
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

/// # Safety
/// `semaphore` is initialized. Always inline through aliases to preserve the
/// actual C caller's return address for cancellation classification.
#[inline(always)]
pub(crate) unsafe fn wait_cp(semaphore: *mut c_void) -> c_int {
    unsafe { wait_common(semaphore, None, true) }
}

/// # Safety
/// `deadline` is a readable absolute timespec and `semaphore` is initialized.
/// `mandatory_cancel` distinguishes POSIX timedwait from glibc clockwait's fast path.
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
