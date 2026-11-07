//! Bounded native cancellation for poll and epoll waits.
//!
//! A native request does not send a signal. Recheck its stable cancellation
//! word between at most 50 ms of kernel waiting. Block signals between slices
//! and atomically install the requested mask inside each kernel wait, so a handler
//! cannot run in an internal gap and lose the public wait's EINTR result.

use frankenlibc_core::pthread::thread::CancellationWait;
use frankenlibc_core::syscall::{self, Timespec};
use std::ffi::c_int;

const KERNEL_SIGSET_BYTES: usize = core::mem::size_of::<u64>();
const NANOS_PER_SECOND: i128 = 1_000_000_000;
const NANOS_PER_MILLISECOND: i64 = 1_000_000;
const SLICE_NS: i64 = 50_000_000;

#[derive(Clone, Copy)]
enum Operation {
    Poll {
        fds: *mut u8,
        nfds: usize,
    },
    Epoll {
        epfd: c_int,
        events: *mut u8,
        maxevents: c_int,
    },
    Epoll2 {
        epfd: c_int,
        events: *mut u8,
        maxevents: c_int,
    },
}

impl Operation {
    fn consumes_notification(self) -> bool {
        matches!(self, Self::Epoll { .. } | Self::Epoll2 { .. })
    }

    /// Execute one bounded wait on the original application descriptors.
    /// No probe drains edge-triggered events or disables a one-shot before the
    /// result is published, and no synthetic descriptor consumes an event slot.
    unsafe fn wait(self, slice: &mut Timespec, mask: *const u8) -> Result<c_int, c_int> {
        // SAFETY: each entry point retains its original kernel arguments. The
        // timeout is owned and bounded, except an invalid epoll_pwait2 timeout
        // passed through solely to preserve EINVAL-versus-ENOSYS precedence.
        unsafe {
            match self {
                Self::Poll { fds, nfds } => syscall::sys_ppoll(
                    fds,
                    nfds,
                    core::ptr::from_mut(slice).cast::<u8>().cast_const(),
                    mask,
                    KERNEL_SIGSET_BYTES,
                ),
                Self::Epoll {
                    epfd,
                    events,
                    maxevents,
                } => syscall::sys_epoll_pwait(
                    epfd,
                    events,
                    maxevents,
                    milliseconds_rounded_up(slice),
                    mask,
                    KERNEL_SIGSET_BYTES,
                ),
                Self::Epoll2 {
                    epfd,
                    events,
                    maxevents,
                } => syscall::sys_epoll_pwait2(
                    epfd,
                    events,
                    maxevents,
                    core::ptr::from_mut(slice).cast::<u8>().cast_const(),
                    mask,
                    KERNEL_SIGSET_BYTES,
                ),
            }
        }
    }
}

/// The millisecond syscall must not expire a fractional final slice early.
/// Its input is always zero or at most SLICE_NS, so rounding cannot overflow.
fn milliseconds_rounded_up(slice: &Timespec) -> c_int {
    debug_assert_eq!(slice.tv_sec, 0);
    debug_assert!((0..=SLICE_NS).contains(&slice.tv_nsec));
    ((slice.tv_nsec + NANOS_PER_MILLISECOND - 1) / NANOS_PER_MILLISECOND) as c_int
}

/// Wait with the original pollfd array and temporary signal mask.
///
/// A request observed after a kernel wait invokes `on_cancel` under the wait's
/// temporary mask. Ordinary returns restore the original mask first. Raw
/// syscalls return errors without changing the caller's errno slot.
///
/// # Safety
/// `fds` must satisfy the kernel poll contract for `nfds`. A non-null timeout
/// points to a readable, aligned, owned 64-bit timespec. The mask is null or
/// remains a kernel-readable signal-set argument; it is never dereferenced by
/// Rust. `cancel` belongs to the calling native thread and remains registered.
/// `on_cancel` may unwind; if it returns, the original mask is restored.
pub(super) unsafe fn wait(
    fds: *mut u8,
    nfds: usize,
    timeout: *const u8,
    mask: *const u8,
    cancel: CancellationWait,
    on_cancel: unsafe extern "C-unwind" fn(),
) -> Result<c_int, c_int> {
    // SAFETY: the caller retains the owned timeout and all poll arguments.
    unsafe {
        wait_operation(
            Operation::Poll { fds, nfds },
            timeout,
            mask,
            cancel,
            on_cancel,
        )
    }
}

/// Wait for epoll events with the millisecond epoll_wait/epoll_pwait contract.
///
/// The integer family keeps using epoll_pwait, so cancellation does not require
/// the newer epoll_pwait2 syscall. Every negative timeout denotes infinity.
///
/// # Safety
/// `events` must satisfy the kernel contract for `maxevents`. The mask and
/// cancellation callback have the same requirements as [`wait`].
pub(super) unsafe fn wait_epoll(
    epfd: c_int,
    events: *mut u8,
    maxevents: c_int,
    timeout: c_int,
    mask: *const u8,
    cancel: CancellationWait,
    on_cancel: unsafe extern "C-unwind" fn(),
) -> Result<c_int, c_int> {
    let duration = Timespec {
        tv_sec: i64::from(timeout.max(0) / 1000),
        tv_nsec: i64::from(timeout.max(0) % 1000) * NANOS_PER_MILLISECOND,
    };
    let timeout = if timeout < 0 {
        core::ptr::null()
    } else {
        core::ptr::from_ref(&duration).cast()
    };
    // SAFETY: duration remains stationary until the shared wait returns.
    unsafe {
        wait_operation(
            Operation::Epoll {
                epfd,
                events,
                maxevents,
            },
            timeout,
            mask,
            cancel,
            on_cancel,
        )
    }
}

/// Wait for epoll events with the nanosecond epoll_pwait2 contract.
///
/// An unavailable epoll_pwait2 still reports ENOSYS; substituting the integer
/// syscall would silently weaken the caller's timeout precision and error ABI.
///
/// # Safety
/// `events` must satisfy the kernel contract for `maxevents`. The timeout,
/// mask and cancellation callback have the same requirements as [`wait`].
pub(super) unsafe fn wait_epoll2(
    epfd: c_int,
    events: *mut u8,
    maxevents: c_int,
    timeout: *const u8,
    mask: *const u8,
    cancel: CancellationWait,
    on_cancel: unsafe extern "C-unwind" fn(),
) -> Result<c_int, c_int> {
    // SAFETY: the caller retains the owned timeout and all epoll arguments.
    unsafe {
        wait_operation(
            Operation::Epoll2 {
                epfd,
                events,
                maxevents,
            },
            timeout,
            mask,
            cancel,
            on_cancel,
        )
    }
}

unsafe fn wait_operation(
    operation: Operation,
    timeout: *const u8,
    mask: *const u8,
    cancel: CancellationWait,
    on_cancel: unsafe extern "C-unwind" fn(),
) -> Result<c_int, c_int> {
    let mut duration = if timeout.is_null() {
        None
    } else {
        // SAFETY: the ABI retained its owned, aligned timeout through this call.
        Some(unsafe { *timeout.cast::<Timespec>() })
    };
    if let Some(time) = duration.as_mut()
        && (time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec))
    {
        // Linux rejects the timeout before reading the mask. Do not introduce
        // a mask access, signal-mask change or clock read on this error path.
        // epoll_pwait2 is newer than the other waits: an unavailable syscall
        // must still report ENOSYS even when its timespec would be invalid.
        if matches!(operation, Operation::Epoll2 { .. }) {
            return unsafe { operation.wait(time, mask) };
        }
        return Err(libc::EINVAL);
    }
    if let Some(time) = duration.as_mut()
        && time.tv_sec == 0
        && time.tv_nsec == 0
    {
        // Immediate polls need no slicing or outer mask change. Keep mutable
        // owned storage: raw ppoll may write through its const timeout pointer.
        return unsafe { operation.wait(time, mask) };
    }
    if cancel.pending() {
        return Err(libc::EINTR);
    }

    let mut guard = SignalMaskGuard::block_all()?;
    let wait_mask = if mask.is_null() {
        core::ptr::from_ref(&guard.original).cast::<u8>()
    } else {
        mask
    };
    // SAFETY: every borrowed control remains live and unmoved through the loop.
    let result = match unsafe { wait_slices(operation, duration, wait_mask, cancel) } {
        Ok(WaitResult::Completed(ready)) => Ok(ready),
        Ok(WaitResult::Cancel) => {
            // The guard has not moved while wait_mask could point into it.
            // Install the temporary mask directly from the all-blocked state:
            // restoring the original first could run a temporarily blocked
            // signal handler before cancellation cleanup.
            unsafe { guard.deliver_cancel(mask, on_cancel) }.and(Err(libc::EINTR))
        }
        Err(error) => Err(error),
    };
    // Restore once before publishing an ordinary result, including when the
    // cancellation callback returned because cancellation became disabled.
    // A restoration error must not be hidden behind a successful wait result.
    guard.restore().and(result)
}

struct SignalMaskGuard {
    original: u64,
    armed: bool,
}

impl SignalMaskGuard {
    fn block_all() -> Result<Self, c_int> {
        let all = u64::MAX;
        let mut original = 0;
        // SAFETY: both pointers name live kernel-width signal sets. The kernel
        // ignores the unblockable SIGKILL/SIGSTOP bits itself.
        unsafe {
            syscall::sys_rt_sigprocmask(
                libc::SIG_SETMASK,
                core::ptr::from_ref(&all).cast(),
                core::ptr::from_mut(&mut original).cast(),
                KERNEL_SIGSET_BYTES,
            )?;
        }
        Ok(Self {
            original,
            armed: true,
        })
    }

    fn restore(mut self) -> Result<(), c_int> {
        self.armed = false;
        restore_mask(self.original)
    }

    unsafe fn deliver_cancel(
        &mut self,
        requested: *const u8,
        on_cancel: unsafe extern "C-unwind" fn(),
    ) -> Result<(), c_int> {
        let mask = if requested.is_null() {
            core::ptr::from_ref(&self.original).cast()
        } else {
            requested
        };
        // Both installing the mask and calling on_cancel may unwind through
        // an application handler. Cleanup must retain the temporary mask;
        // never let this guard restore the original during that unwind.
        self.armed = false;
        let installed = unsafe { install_mask(mask) };
        if installed.is_ok() {
            unsafe { on_cancel() };
        }
        // A returning callback has not canceled the thread. Restore the
        // original mask on the normal exit, including mask-install errors.
        self.armed = true;
        installed
    }
}

impl Drop for SignalMaskGuard {
    fn drop(&mut self) {
        if self.armed {
            self.armed = false;
            let _ = restore_mask(self.original);
        }
    }
}

// Restoring a mask can deliver an application handler. Keep that syscall in
// a frame with no drop state; the guard is already disarmed on the normal path.
#[inline(never)]
fn restore_mask(original: u64) -> Result<(), c_int> {
    // SAFETY: original is a live copy of the kernel's complete signal mask.
    unsafe { install_mask(core::ptr::from_ref(&original).cast()) }
}

#[inline(never)]
unsafe fn install_mask(mask: *const u8) -> Result<(), c_int> {
    // SAFETY: the pointer remains a kernel-validated signal-set argument.
    unsafe {
        syscall::sys_rt_sigprocmask(
            libc::SIG_SETMASK,
            mask,
            core::ptr::null_mut(),
            KERNEL_SIGSET_BYTES,
        )
    }
}

fn monotonic_nanoseconds() -> Result<i128, c_int> {
    let mut now = Timespec::default();
    // SAFETY: the output is writable, correctly sized kernel timespec storage.
    unsafe {
        syscall::sys_clock_gettime(libc::CLOCK_MONOTONIC, core::ptr::from_mut(&mut now).cast())?;
    }
    Ok(i128::from(now.tv_sec) * NANOS_PER_SECOND + i128::from(now.tv_nsec))
}

/// Return a relative slice and whether its expiration ends the original wait.
fn next_slice(deadline: Option<i128>, now: i128) -> (Timespec, bool) {
    let remaining = deadline.map(|end| (end - now).max(0));
    let nanoseconds = remaining
        .unwrap_or(i128::from(SLICE_NS))
        .min(i128::from(SLICE_NS));
    (
        Timespec {
            tv_sec: 0,
            tv_nsec: nanoseconds as i64,
        },
        remaining.is_some_and(|left| left <= i128::from(SLICE_NS)),
    )
}

enum WaitResult {
    Completed(c_int),
    Cancel,
}

// Keep the raw wait outside the guard-owning frame. This function owns only
// plain values, and never invokes cancellation or retries a handler's EINTR.
#[inline(never)]
unsafe fn wait_slices(
    operation: Operation,
    duration: Option<Timespec>,
    mask: *const u8,
    cancel: CancellationWait,
) -> Result<WaitResult, c_int> {
    let deadline = match duration {
        Some(time) => Some(
            monotonic_nanoseconds()?
                + i128::from(time.tv_sec) * NANOS_PER_SECOND
                + i128::from(time.tv_nsec),
        ),
        None => None,
    };
    let mut waited = false;
    loop {
        if cancel.pending() {
            // A request before the first kernel wait retains the entry mask.
            // Between slices the public wait still owns its temporary mask.
            return if waited {
                Ok(WaitResult::Cancel)
            } else {
                Err(libc::EINTR)
            };
        }
        let now = if deadline.is_some() {
            monotonic_nanoseconds()?
        } else {
            0
        };
        let (mut slice, final_slice) = next_slice(deadline, now);
        // SAFETY: the original output array and mask outlive this call. The
        // kernel may update only our timeout, never the caller's const input.
        let result = unsafe { operation.wait(&mut slice, mask) };
        // epoll can consume an edge-triggered notification or disable a
        // one-shot even though it does not consume the associated I/O. Once
        // it produces events, publish them and leave a racing request pending
        // for the next cancellation point. poll has no such ownership transfer.
        let acquired =
            operation.consumes_notification() && matches!(result, Ok(ready) if ready > 0);
        if !acquired && cancel.pending() && matches!(result, Ok(_) | Err(libc::EINTR)) {
            return Ok(WaitResult::Cancel);
        }
        match result {
            Ok(0) if !final_slice => waited = true,
            Ok(ready) => return Ok(WaitResult::Completed(ready)),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_slices_keep_one_deadline_and_the_final_fraction() {
        let end = Some(120_000_000);
        assert_eq!(next_slice(end, 0).0.tv_nsec, 50_000_000);
        assert!(!next_slice(end, 0).1);
        assert_eq!(next_slice(end, 50_000_000).0.tv_nsec, 50_000_000);
        assert!(!next_slice(end, 50_000_000).1);
        assert_eq!(next_slice(end, 100_000_000).0.tv_nsec, 20_000_000);
        assert!(next_slice(end, 100_000_000).1);
        assert_eq!(next_slice(end, 130_000_000).0.tv_nsec, 0);
        assert!(next_slice(end, 130_000_000).1);
        assert!(!next_slice(None, i128::from(i64::MAX)).1);
        for (nanoseconds, milliseconds) in [
            (0, 0),
            (1, 1),
            (999_999, 1),
            (1_000_000, 1),
            (1_000_001, 2),
            (49_999_999, 50),
            (50_000_000, 50),
        ] {
            let (slice, final_slice) = next_slice(Some(nanoseconds), 0);
            assert!(final_slice);
            assert_eq!(milliseconds_rounded_up(&slice), milliseconds);
        }
    }

    #[test]
    fn time_t_extremes_do_not_wrap_or_truncate_the_wait() {
        let huge = i128::from(i64::MAX) * NANOS_PER_SECOND + 999_999_999;
        let early = i128::from(i64::MIN) * NANOS_PER_SECOND;
        assert_eq!(next_slice(Some(huge), early).0.tv_nsec, SLICE_NS);
        assert!(!next_slice(Some(huge), early).1);
        assert_eq!(next_slice(Some(early), huge).0.tv_nsec, 0);
        assert!(next_slice(Some(early), huge).1);
    }
}
