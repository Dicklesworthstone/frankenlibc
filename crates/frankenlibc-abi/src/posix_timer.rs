//! POSIX SIGEV_THREAD timers: kernel expiration accounting with one signal
//! receiver per process and a fresh detached pthread for each notification.
//!
//! User handles contain a tag and monotonically allocated token, never a raw
//! pointer into the registry. A queued event for a deleted timer cannot reach
//! a subsequently allocated timer or freed callback state.

use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use frankenlibc_core::syscall as raw;

use super::aio_completion::{self, Notice};
use crate::pthread_abi::TimerThreadAttributes;
use crate::util::{ArtifactHashMap, artifact_hash_map};

const HANDLE_TAG: usize = 1usize << (usize::BITS - 1);
// Linux/NPTL reserves 32 and 33 from the application signal namespace. The
// receiver consumes only thread-directed timer events on 32. It disables
// cancellation and leaves 33 unblocked so host setxid synchronization works.
const TIMER_SIGNAL: c_int = 32;
const TIMER_SIGNAL_MASK: u64 = 1u64 << (TIMER_SIGNAL - 1);
const HELPER_STACK_SIZE: usize = 256 * 1024;

struct ThreadTimer {
    kernel_id: c_int,
    notice: Notice,
    attributes: TimerThreadAttributes,
}

struct TimerRuntime {
    pid: c_int,
    helper_tid: AtomicI32,
    helper_start: Mutex<()>,
    timers: Mutex<ArtifactHashMap<usize, Arc<ThreadTimer>>>,
}

static TIMER_RUNTIME: AtomicPtr<TimerRuntime> = AtomicPtr::new(std::ptr::null_mut());
// Fork resets the registry, but must not recycle any handle copied from the
// parent. This lock-free allocator is inherited with its current value, so a
// child's new timers cannot alias stale handles from an ancestor process.
static NEXT_TIMER_TOKEN: AtomicUsize = AtomicUsize::new(1);

fn runtime() -> &'static TimerRuntime {
    let pid = raw::sys_getpid();
    loop {
        let current = TIMER_RUNTIME.load(Ordering::Acquire);
        // SAFETY: a published runtime lives for the process lifetime. Its pid
        // is immutable, including in the copied address space after fork.
        if !current.is_null() && unsafe { (*current).pid == pid } {
            return unsafe { &*current };
        }
        let fresh = Box::into_raw(Box::new(TimerRuntime {
            pid,
            helper_tid: AtomicI32::new(0),
            helper_start: Mutex::new(()),
            timers: Mutex::new(artifact_hash_map()),
        }));
        match TIMER_RUNTIME.compare_exchange(current, fresh, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                // POSIX timers and the helper are not inherited across fork.
                // Do not drop an inherited runtime: its locks may have belonged
                // to vanished parent threads. A fresh process gets fresh locks.
                // SAFETY: fresh is now published and intentionally persistent.
                return unsafe { &*fresh };
            }
            Err(_) => {
                // SAFETY: this unpublished candidate never started a helper.
                unsafe { drop(Box::from_raw(fresh)) };
            }
        }
    }
}

fn wake_helper_start(runtime: &TimerRuntime) {
    // SAFETY: the persistent runtime owns this aligned futex word.
    let _ = unsafe {
        raw::sys_futex(
            &runtime.helper_tid as *const AtomicI32 as *const u32,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            c_int::MAX as u32,
            0,
            0,
            0,
        )
    };
}

unsafe extern "C-unwind" fn notification_start(arg: *mut c_void) -> *mut c_void {
    aio_completion::detach_current();
    // SAFETY: a successful pthread_create transferred this allocation exactly
    // once. Copy and release it before user code can exit, cancel or reenter.
    let notice = *unsafe { Box::from_raw(arg.cast::<Notice>()) };
    if let Notice::Thread { callback, value } = notice {
        // SAFETY: the callback and sigval were captured from a live sigevent.
        // This frame and the callback type permit pthread_exit/forced unwind.
        // Unlike an AIO worker, this thread has no implementation-generated
        // SIGPIPE to drain: any pending process signal belongs to application
        // code and must remain pending until the application consumes it.
        unsafe {
            callback(libc::sigval {
                sival_ptr: value as *mut c_void,
            })
        };
    }
    std::ptr::null_mut()
}

unsafe extern "C-unwind" fn helper_start(arg: *mut c_void) -> *mut c_void {
    // SAFETY: the creator passes the persistent, published runtime address.
    let runtime = unsafe { &*arg.cast::<TimerRuntime>() };
    aio_completion::detach_current();
    // This private receiver is not a cancellation target. Blocking signal 32
    // cannot delay a cancellation request on any application callback thread.
    let cancel_rc = unsafe {
        crate::pthread_abi::pthread_setcancelstate(1, std::ptr::null_mut()) // PTHREAD_CANCEL_DISABLE
    };
    // All application signals and SIGCANCEL are blocked; SIGSETXID stays open.
    let receiver_mask = !(1u64 << 32);
    let mask_result = unsafe {
        raw::sys_rt_sigprocmask(
            libc::SIG_SETMASK,
            (&receiver_mask as *const u64).cast(),
            std::ptr::null_mut(),
            8,
        )
    };
    let setup_error = if cancel_rc != 0 {
        Some(cancel_rc)
    } else {
        mask_result.err()
    };
    if let Some(error) = setup_error {
        runtime.helper_tid.store(-error, Ordering::Release);
        wake_helper_start(runtime);
        return std::ptr::null_mut();
    }
    runtime.helper_tid.store(raw::sys_gettid(), Ordering::Release);
    wake_helper_start(runtime);

    loop {
        // SAFETY: siginfo_t is plain kernel output storage. Both supported
        // Linux LP64 targets use an eight-byte kernel signal set.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let received = unsafe {
            raw::sys_rt_sigtimedwait(
                (&TIMER_SIGNAL_MASK as *const u64).cast(),
                (&mut info as *mut libc::siginfo_t).cast(),
                std::ptr::null(),
                8,
            )
        };
        match received {
            Err(libc::EINTR) => continue,
            Err(error) => {
                runtime.helper_tid.store(-error, Ordering::Release);
                return std::ptr::null_mut();
            }
            Ok(signal) if signal == TIMER_SIGNAL && info.si_code == libc::SI_TIMER => {}
            _ => continue,
        }
        // SAFETY: SI_TIMER selects the timer/sigval member of siginfo_t.
        let token = unsafe { info.si_value().sival_ptr as usize };
        let timer = {
            let timers = runtime.timers.lock().unwrap_or_else(|e| e.into_inner());
            timers.get(&token).cloned()
        };
        let Some(timer) = timer else {
            // Deletion removed ownership before this queued event was read.
            continue;
        };
        let notice = Box::into_raw(Box::new(timer.notice));
        // No timer-registry lock is held while creating a thread or calling
        // application code. The Arc retains the attribute snapshot through
        // pthread_create even if the timer is deleted concurrently.
        let result = unsafe {
            aio_completion::spawn(notification_start, notice.cast(), timer.attributes.as_ptr())
        };
        if result.is_err() {
            // SAFETY: failed creation did not transfer the callback allocation.
            unsafe { drop(Box::from_raw(notice)) };
        }
    }
}

impl TimerRuntime {
    fn ensure_helper(&'static self) -> Result<c_int, c_int> {
        let existing = self.helper_tid.load(Ordering::Acquire);
        if existing != 0 {
            return if existing > 0 { Ok(existing) } else { Err(-existing) };
        }
        let _start = self.helper_start.lock().unwrap_or_else(|e| e.into_inner());
        let existing = self.helper_tid.load(Ordering::Acquire);
        if existing != 0 {
            return if existing > 0 { Ok(existing) } else { Err(-existing) };
        }
        // The helper has implementation-owned attributes, independent of the
        // application's notification stack, affinity and scheduling settings.
        // SAFETY: initialization establishes a live local attribute object.
        let mut attr: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
        let init = unsafe { crate::pthread_abi::pthread_attr_init(&mut attr) };
        if init != 0 {
            return Err(init);
        }
        let stack = unsafe {
            crate::pthread_abi::pthread_attr_setstacksize(&mut attr, HELPER_STACK_SIZE)
        };
        let detached = unsafe {
            crate::pthread_abi::pthread_attr_setdetachstate(&mut attr, libc::PTHREAD_CREATE_DETACHED)
        };
        let spawned = if stack != 0 {
            Err(stack)
        } else if detached != 0 {
            Err(detached)
        } else {
            // SAFETY: self is persistent. pthread_create consumes attr before
            // returning and the detached worker never borrows that local object.
            unsafe {
                aio_completion::spawn(
                    helper_start,
                    (self as *const Self).cast_mut().cast(),
                    &attr,
                )
            }
        };
        let _ = unsafe { crate::pthread_abi::pthread_attr_destroy(&mut attr) };
        spawned?;
        loop {
            let tid = self.helper_tid.load(Ordering::Acquire);
            if tid != 0 {
                return if tid > 0 { Ok(tid) } else { Err(-tid) };
            }
            // SAFETY: self is persistent; spurious wakes/EINTR recheck the word.
            let _ = unsafe {
                raw::sys_futex(
                    &self.helper_tid as *const AtomicI32 as *const u32,
                    libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                    0,
                    0,
                    0,
                    0,
                )
            };
        }
    }
}

pub(super) fn is_thread_timer(timer: *mut c_void) -> bool {
    timer as usize & HANDLE_TAG != 0
}

/// Create an initially disarmed callback timer. The kernel observes the
/// creating thread's clock, including CLOCK_THREAD_CPUTIME_ID, not the helper's.
pub(super) unsafe fn create(
    clock: libc::clockid_t,
    event: *const libc::sigevent,
) -> Result<*mut c_void, c_int> {
    // SAFETY: timer_create keeps event and its attributes live through this call.
    let (notice, attributes) = unsafe { Notice::read(event) }?;
    if !matches!(notice, Notice::Thread { .. }) {
        return Err(libc::EINVAL);
    }
    let attributes = unsafe { TimerThreadAttributes::new(attributes) }?;
    let runtime = runtime();
    let tid = runtime.ensure_helper()?;
    let token = NEXT_TIMER_TOKEN
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            (next < HANDLE_TAG).then_some(next + 1)
        })
        .map_err(|_| libc::EAGAIN)?;
    // SAFETY: the Linux sigevent union exposes the thread-ID variant through
    // libc. The sigval carries a registry token, never dereferenceable storage.
    let mut kernel_event: libc::sigevent = unsafe { std::mem::zeroed() };
    kernel_event.sigev_notify = libc::SIGEV_THREAD_ID;
    kernel_event.sigev_signo = TIMER_SIGNAL;
    kernel_event.sigev_notify_thread_id = tid;
    kernel_event.sigev_value.sival_ptr = token as *mut c_void;
    let mut kernel_id = 0;
    unsafe {
        raw::sys_timer_create(
            clock,
            (&kernel_event as *const libc::sigevent) as usize,
            &mut kernel_id,
        )
    }?;
    let timer = Arc::new(ThreadTimer {
        kernel_id,
        notice,
        attributes,
    });
    runtime
        .timers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(token, timer);
    Ok((HANDLE_TAG | token) as *mut c_void)
}

/// Keep deletion and raw kernel-id use serialized. No callback or blocking
/// wait occurs while holding this mutex, so callbacks may freely reenter.
pub(super) fn with_kernel_id<T>(
    timer: *mut c_void,
    operation: impl FnOnce(c_int) -> Result<T, c_int>,
) -> Result<T, c_int> {
    if !is_thread_timer(timer) {
        return operation(timer as c_int);
    }
    let timers = runtime().timers.lock().unwrap_or_else(|e| e.into_inner());
    let timer = timers.get(&(timer as usize & !HANDLE_TAG)).ok_or(libc::EINVAL)?;
    operation(timer.kernel_id)
}

pub(super) fn delete(timer: *mut c_void) -> Result<(), c_int> {
    if !is_thread_timer(timer) {
        return raw::sys_timer_delete(timer as c_int);
    }
    let removed = {
        let mut timers = runtime().timers.lock().unwrap_or_else(|e| e.into_inner());
        let token = timer as usize & !HANDLE_TAG;
        let timer = timers.get(&token).ok_or(libc::EINVAL)?;
        raw::sys_timer_delete(timer.kernel_id)?;
        timers.remove(&token)
    };
    // Attribute destruction takes its own registry lock; keep it outside the
    // timer lock. Active notification creation retains its independent Arc.
    drop(removed);
    Ok(())
}
