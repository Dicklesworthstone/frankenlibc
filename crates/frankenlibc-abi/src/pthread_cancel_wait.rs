//! Native cancellation-aware waits on an existing synchronization word.
//!
//! The operation word and the calling thread's immortal cancellation word are
//! registered in one `futex_waitv` call. A request before registration fails the
//! value comparison; a request after registration wakes the second word. The
//! caller delivers cancellation only after this module returns from the kernel.
//! No signal handler, allocation, extra descriptor, or foreign TCB is involved.

use frankenlibc_core::pthread::thread::CancellationWait;
use frankenlibc_core::syscall::{self, FutexWaitV, Timespec};

const FUTEX_32: u32 = 2;
const NANOS_PER_SECOND: i128 = 1_000_000_000;
// Only kernels without waitv (or filters that deny it) poll. Relative slices
// keep cancellation bounded even if CLOCK_REALTIME is moved backwards.
const FALLBACK_SLICE_NS: i64 = 50_000_000;

/// Only the wait forms used by semaphores, condition variables, and joins are
/// interchangeable with waitv. In particular, a selective bitset is not.
pub(super) fn supported(operation: i32, timeout: usize, bitset: u32) -> bool {
    match operation & !(libc::FUTEX_PRIVATE_FLAG | libc::FUTEX_CLOCK_REALTIME) {
        libc::FUTEX_WAIT => timeout == 0 && operation & libc::FUTEX_CLOCK_REALTIME == 0,
        libc::FUTEX_WAIT_BITSET => bitset == u32::MAX,
        _ => false,
    }
}

/// Sleep until either the operation changes/wakes, cancellation is requested,
/// the original absolute deadline expires, or the kernel reports an error.
/// The caller must pass any unconsumed operation wake to a peer before acting
/// on cancellation; this module neither consumes tokens nor unwinds.
///
/// # Safety
/// `word` must remain a live aligned futex word through this call. `timeout`
/// must be zero or a readable absolute 64-bit timespec. The operation must pass
/// `supported`, and `cancel` must describe the current native thread.
pub(super) unsafe fn wait(
    word: *mut u32,
    operation: i32,
    expected: u32,
    timeout: usize,
    cancel: CancellationWait,
) -> Result<isize, i32> {
    let deadline = if timeout == 0 {
        None
    } else {
        // SAFETY: the caller provides a readable 64-bit absolute timespec.
        Some(unsafe { *(timeout as *const Timespec) })
    };
    let clock = if operation & libc::FUTEX_CLOCK_REALTIME != 0 {
        libc::CLOCK_REALTIME
    } else {
        libc::CLOCK_MONOTONIC
    };
    let private = operation & libc::FUTEX_PRIVATE_FLAG;
    let waiters = [
        FutexWaitV {
            val: u64::from(expected),
            uaddr: word as usize as u64,
            flags: FUTEX_32 | private as u32,
            reserved: 0,
        },
        FutexWaitV {
            val: u64::from(cancel.expected()),
            uaddr: cancel.address() as usize as u64,
            flags: FUTEX_32 | libc::FUTEX_PRIVATE_FLAG as u32,
            reserved: 0,
        },
    ];
    if cancel.pending() {
        return Err(libc::EINTR);
    }
    // SAFETY: both words remain live while the caller is parked. The descriptor
    // points into the static cancellation table, never a remotely freed handle.
    let result = unsafe {
        syscall::sys_futex_waitv(
            waiters.as_ptr(),
            waiters.len() as u32,
            0,
            deadline
                .as_ref()
                .map_or(core::ptr::null(), |time| (time as *const Timespec).cast()),
            clock,
        )
    }
    .map(|index| index as isize);
    match result {
        Err(libc::ENOSYS | libc::EPERM | libc::EACCES) => {
            // Seccomp policy may differ between threads. Do not globally cache
            // a denied syscall and degrade every other thread to polling.
            unsafe { wait_fallback(word, private, expected, deadline, clock, cancel) }
        }
        result => result,
    }
}

/// A relative timeout capped independently of the absolute deadline's epoch.
/// Wide arithmetic handles deadlines near time_t::MAX without overflow.
fn fallback_slice(deadline: Option<Timespec>, now: Timespec) -> Timespec {
    let nanoseconds = deadline.map_or(i128::from(FALLBACK_SLICE_NS), |end| {
        ((i128::from(end.tv_sec) - i128::from(now.tv_sec)) * NANOS_PER_SECOND
            + i128::from(end.tv_nsec)
            - i128::from(now.tv_nsec))
        .clamp(0, i128::from(FALLBACK_SLICE_NS))
    });
    Timespec {
        tv_sec: 0,
        tv_nsec: nanoseconds as i64,
    }
}

unsafe fn wait_fallback(
    word: *mut u32,
    private: i32,
    expected: u32,
    deadline: Option<Timespec>,
    clock: i32,
    cancel: CancellationWait,
) -> Result<isize, i32> {
    if let Some(end) = deadline
        && (end.tv_sec < 0 || !(0..1_000_000_000).contains(&end.tv_nsec))
    {
        return Err(libc::EINVAL);
    }
    loop {
        if cancel.pending() {
            return Err(libc::EINTR);
        }
        let mut now = Timespec::default();
        if deadline.is_some() {
            // SAFETY: now is writable and has the kernel's timespec layout.
            unsafe {
                syscall::sys_clock_gettime(clock, (&mut now as *mut Timespec).cast())?;
            }
        }
        let slice = fallback_slice(deadline, now);
        // A zero-length wait still compares the operation word before returning
        // ETIMEDOUT, preserving the original futex's EAGAIN precedence. Earlier
        // slice expirations stay internal and never become a user timeout.
        let result = unsafe {
            syscall::sys_futex(
                word,
                libc::FUTEX_WAIT | private,
                expected,
                &slice as *const Timespec as usize,
                0,
                0,
            )
        };
        match result {
            Err(libc::ETIMEDOUT) if slice.tv_nsec != 0 => {}
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(seconds: i64, nanoseconds: i64) -> Timespec {
        Timespec {
            tv_sec: seconds,
            tv_nsec: nanoseconds,
        }
    }

    #[test]
    fn waitv_admission_preserves_futex_operation_and_bitset_semantics() {
        for private in [0, libc::FUTEX_PRIVATE_FLAG] {
            assert!(supported(libc::FUTEX_WAIT | private, 0, 0));
            assert!(!supported(libc::FUTEX_WAIT | private, 1, 0));
            for clock in [0, libc::FUTEX_CLOCK_REALTIME] {
                let operation = libc::FUTEX_WAIT_BITSET | private | clock;
                assert!(supported(operation, 1, u32::MAX));
                assert!(!supported(operation, 1, 1));
                assert!(!supported(operation, 1, 0));
            }
        }
        assert!(!supported(libc::FUTEX_WAKE, 0, 0));
        assert!(!supported(
            libc::FUTEX_WAIT | libc::FUTEX_CLOCK_REALTIME,
            0,
            0
        ));
    }

    #[test]
    fn fallback_keeps_the_original_deadline_across_many_slices() {
        let end = Some(time(10, 120_000_000));
        assert_eq!(fallback_slice(end, time(10, 0)), time(0, 50_000_000));
        assert_eq!(
            fallback_slice(end, time(10, 50_000_000)),
            time(0, 50_000_000)
        );
        assert_eq!(
            fallback_slice(end, time(10, 100_000_000)),
            time(0, 20_000_000)
        );
        assert_eq!(fallback_slice(end, time(10, 120_000_000)), time(0, 0));
        assert_eq!(fallback_slice(end, time(11, 0)), time(0, 0));
    }

    #[test]
    fn fallback_handles_nanosecond_borrow_and_clock_steps() {
        let end = Some(time(11, 10_000_000));
        assert_eq!(
            fallback_slice(end, time(10, 990_000_000)),
            time(0, 20_000_000)
        );
        assert_eq!(fallback_slice(end, time(1, 0)), time(0, 50_000_000));
        assert_eq!(fallback_slice(end, time(20, 0)), time(0, 0));
        assert_eq!(fallback_slice(None, time(20, 0)), time(0, 50_000_000));
    }

    #[test]
    fn fallback_extreme_time_t_values_do_not_wrap() {
        assert_eq!(
            fallback_slice(Some(time(i64::MAX, 999_999_999)), time(i64::MIN, 0)),
            time(0, 50_000_000)
        );
        assert_eq!(
            fallback_slice(Some(time(i64::MIN, 0)), time(i64::MAX, 999_999_999)),
            time(0, 0)
        );
    }
}
