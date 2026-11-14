//! Bounded native cancellation for descriptor, sleep and child-process waits.
//!
//! A native request does not send a signal. Recheck its stable cancellation
//! word between at most 50 ms of kernel waiting. Block signals between slices
//! and atomically install the requested mask inside each kernel wait, so a handler
//! cannot run in an internal gap and lose the public wait's EINTR result.

use frankenlibc_core::pthread::thread::CancellationWait;
use frankenlibc_core::syscall::{self, Timespec};
use std::ffi::c_int;

use crate::io_abi::iov_snapshot::copy_user_bytes;

const KERNEL_SIGSET_BYTES: usize = core::mem::size_of::<u64>();
const NANOS_PER_SECOND: i128 = 1_000_000_000;
const NANOS_PER_MILLISECOND: i64 = 1_000_000;
const SLICE_NS: i64 = 50_000_000;
const STICKY_TIMEOUTS: usize = 0x0400_0000;

/// select publishes a mutable microsecond remainder; pselect owns an internal
/// nanosecond copy and must never publish it to the application's const input.
#[derive(Clone, Copy)]
pub(super) enum SelectTimeout {
    Timeval(*mut u8),
    Timespec(*const u8),
}

impl SelectTimeout {
    unsafe fn duration(&self) -> Result<Option<Timespec>, c_int> {
        match *self {
            Self::Timeval(pointer) if !pointer.is_null() => {
                let mut value = libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                };
                // SAFETY: import caller storage through a fault-checked kernel
                // copy, including unaligned timevals, without forming a reference.
                unsafe {
                    copy_user_bytes(
                        pointer,
                        core::ptr::from_mut(&mut value).cast(),
                        core::mem::size_of::<libc::timeval>(),
                    )?;
                }
                // Leave Linux's normalization of out-of-range microseconds and
                // rejection of negative fields to the original select syscall.
                let nanoseconds = if (0..1_000_000).contains(&value.tv_usec) {
                    value.tv_usec * 1000
                } else {
                    -1
                };
                Ok(Some(Timespec {
                    tv_sec: value.tv_sec,
                    tv_nsec: nanoseconds,
                }))
            }
            Self::Timespec(pointer) if !pointer.is_null() => {
                // SAFETY: the ABI keeps its prepared, aligned timeout copy live.
                Ok(Some(unsafe { *pointer.cast::<Timespec>() }))
            }
            _ => Ok(None),
        }
    }
}

const SELECT_WORDS: usize = libc::FD_SETSIZE / u64::BITS as usize;

/// Keep the caller's initial interest masks across empty select slices. The
/// kernel still reads and writes the original buffers, preserving its exact
/// fd-table clipping, output-fault behavior and aliases between the three sets.
/// No intermediate mask is observable to a signal handler: signals remain
/// blocked between the atomic pselect6 waits.
struct SelectMasks {
    pointers: [*mut u8; 3],
    original: [[u64; SELECT_WORDS]; 3],
    words: usize,
}

impl SelectMasks {
    unsafe fn capture(nfds: c_int, pointers: [*mut u8; 3]) -> Result<Self, c_int> {
        let mut masks = Self {
            pointers,
            original: [[0; SELECT_WORDS]; 3],
            words: (nfds as usize).div_ceil(u64::BITS as usize),
        };
        for (pointer, original) in masks.pointers.into_iter().zip(&mut masks.original) {
            if !pointer.is_null() {
                // SAFETY: original owns initialized storage for the requested
                // word count; caller pointers are only kernel-copy sources.
                unsafe {
                    copy_user_bytes(
                        pointer,
                        original.as_mut_ptr().cast(),
                        masks.words * core::mem::size_of::<u64>(),
                    )?;
                }
            }
        }
        Ok(masks)
    }

    unsafe fn restore(&self) -> Result<(), c_int> {
        for (pointer, original) in self.pointers.into_iter().zip(&self.original) {
            if pointer.is_null() || self.words == 0 {
                continue;
            }
            let mut current = [0u64; SELECT_WORDS];
            // SAFETY: both extents have the captured word count. A concurrent
            // caller unmap is reported as EFAULT instead of a Rust dereference.
            unsafe {
                copy_user_bytes(
                    pointer,
                    current.as_mut_ptr().cast(),
                    self.words * core::mem::size_of::<u64>(),
                )?;
            }
            for word in 0..self.words {
                if current[word] != original[word] {
                    // Linux may clip nfds to its smaller fd-table capacity.
                    // Restore only words it changed: an untouched, readable but
                    // unwritable suffix must not introduce a new output fault.
                    // SAFETY: the source is an owned initialized word; the
                    // destination is validated by the kernel copier.
                    unsafe {
                        copy_user_bytes(
                            core::ptr::from_ref(&original[word]).cast(),
                            pointer.add(word * core::mem::size_of::<u64>()),
                            core::mem::size_of::<u64>(),
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Wait on ordinary fd_set inputs without losing their interest bits between
/// slices. Extended Linux bitsets, unavailable snapshots and unusual timeval
/// syntax retain the original syscall rather than acquiring new ABI errors.
///
/// # Safety
/// The pointers retain the public select/pselect lifetime contract. A Timespec
/// timeout is the ABI's owned copy; a Timeval timeout remains caller storage.
/// The cancellation descriptor and callback have the same contract as [`wait`].
pub(super) unsafe fn wait_select(
    nfds: c_int,
    pointers: [*mut u8; 3],
    timeout: SelectTimeout,
    mask: *const u8,
    cancel: CancellationWait,
    on_cancel: unsafe extern "C-unwind" fn(),
) -> Option<Result<c_int, c_int>> {
    if !(0..=libc::FD_SETSIZE as c_int).contains(&nfds) {
        return None;
    }
    let duration = match unsafe { timeout.duration() } {
        Ok(duration) => duration,
        // No input or output has changed. Let the original syscall distinguish
        // EFAULT from a snapshot mechanism unavailable under the caller's policy.
        Err(_) => return None,
    };
    if duration.is_some_and(|time| {
        time.tv_sec < 0
            || !(0..1_000_000_000).contains(&time.tv_nsec)
            || (time.tv_sec == 0 && time.tv_nsec == 0)
    }) {
        return None;
    }
    // Linux can read fewer words than nfds names when its fd table is smaller.
    // If the additional snapshot extent is inaccessible, preserve that syscall
    // behavior through the original path rather than manufacturing EFAULT.
    let masks = match unsafe { SelectMasks::capture(nfds, pointers) } {
        Ok(masks) => masks,
        Err(_) => return None,
    };
    let mut guard = match SignalMaskGuard::block_all() {
        Ok(guard) => guard,
        Err(error) => return Some(Err(error)),
    };
    let mut publish_timeout = false;
    if let SelectTimeout::Timeval(pointer) = timeout
        && !pointer.is_null()
    {
        // select's STICKY_TIMEOUTS personality leaves the caller's timeval
        // untouched. If the query is denied, retain the original syscall.
        // SAFETY: a read-only per-thread personality query has no pointer args.
        let persona =
            unsafe { syscall::syscall1(libc::SYS_personality as usize, u32::MAX as usize) };
        if (-4095..0).contains(&(persona as isize)) {
            return match guard.restore() {
                Ok(()) => None,
                Err(error) => Some(Err(error)),
            };
        }
        publish_timeout = persona & STICKY_TIMEOUTS == 0;
    }
    let original_mask = guard.original;
    let wait_mask = if mask.is_null() {
        core::ptr::from_ref(&original_mask).cast::<u8>()
    } else {
        mask
    };
    // SAFETY: masks and the original signal-set copy remain stationary until
    // the bounded loop returns or the public cancellation callback unwinds.
    let outcome = unsafe { select_slices(nfds, &masks, duration, wait_mask, &mut guard, cancel) };
    let (result, remaining) = match outcome {
        Ok((WaitResult::Completed(ready), remaining)) => (Ok(ready), remaining),
        Ok((WaitResult::Cancel, _)) => (
            unsafe { guard.deliver_cancel(mask, on_cancel) }.and(Err(libc::EINTR)),
            None,
        ),
        Err((error, remaining)) => (Err(error), remaining),
    };
    let result = guard.restore().and(result);
    if publish_timeout
        && let (SelectTimeout::Timeval(pointer), Some(remaining)) = (timeout, remaining)
    {
        let value = libc::timeval {
            tv_sec: remaining.tv_sec,
            tv_usec: remaining.tv_nsec / 1000,
        };
        // SAFETY: initialized owned timeval; a read-only/unmapped destination
        // returns EFAULT, just as the original select timeout writeback does.
        if let Err(error) = unsafe {
            copy_user_bytes(
                core::ptr::from_ref(&value).cast(),
                pointer,
                core::mem::size_of::<libc::timeval>(),
            )
        } {
            return Some(Err(error));
        }
    }
    Some(result)
}

// Like the other sliced waits, this frame owns no Drop state. Disarm the outer
// mask guard while an application signal handler may unwind from pselect6.
#[inline(never)]
unsafe fn select_slices(
    nfds: c_int,
    masks: &SelectMasks,
    duration: Option<Timespec>,
    mask: *const u8,
    guard: &mut SignalMaskGuard,
    cancel: CancellationWait,
) -> Result<(WaitResult, Option<Timespec>), (c_int, Option<Timespec>)> {
    let deadline = match duration {
        Some(time) => Some(
            monotonic_nanoseconds().map_err(|error| (error, None))?
                + i128::from(time.tv_sec) * NANOS_PER_SECOND
                + i128::from(time.tv_nsec),
        ),
        None => None,
    };
    let sig_data = [mask as usize, KERNEL_SIGSET_BYTES];
    let mut waited = false;
    loop {
        if cancel.pending() {
            return if waited {
                Ok((WaitResult::Cancel, None))
            } else {
                Err((libc::EINTR, None))
            };
        }
        let now = if deadline.is_some() {
            monotonic_nanoseconds().map_err(|error| (error, None))?
        } else {
            0
        };
        let (mut slice, final_slice) = next_slice(deadline, now);
        let unscheduled = deadline.map(|end| (end - now).max(0) - i128::from(slice.tv_nsec));
        guard.armed = false;
        // SAFETY: the original fd_set pointers remain kernel-validated. The
        // timeout and pselect6 mask descriptor are owned initialized storage.
        let result = unsafe {
            syscall::sys_pselect6(
                nfds,
                masks.pointers[0],
                masks.pointers[1],
                masks.pointers[2],
                core::ptr::from_mut(&mut slice).cast::<u8>().cast_const(),
                sig_data.as_ptr().cast(),
            )
        };
        guard.armed = true;
        // Kernel remainder writeback occurs before a signal handler runs.
        // Preserve it rather than deducting handler time from select's result.
        let remaining = unscheduled.map(|unscheduled| {
            sleep_remainder(
                unscheduled
                    + i128::from(slice.tv_sec) * NANOS_PER_SECOND
                    + i128::from(slice.tv_nsec),
            )
        });
        if matches!(result, Ok(0)) && !final_slice {
            // SAFETY: a successful empty wait cleared only kernel-written
            // output words; restore interest before another slice or cleanup.
            unsafe { masks.restore() }.map_err(|error| (error, remaining))?;
        }
        if cancel.pending() && matches!(result, Ok(_) | Err(libc::EINTR)) {
            return Ok((WaitResult::Cancel, None));
        }
        match result {
            Ok(0) if !final_slice => waited = true,
            Ok(ready) => return Ok((WaitResult::Completed(ready), remaining)),
            Err(error) => return Err((error, remaining)),
        }
    }
}

/// The sleep boundary publishes a remainder only for an interrupted relative
/// wait. Unsupported forms retain their original raw syscall, including its
/// argument validation and zero-duration behavior.
pub(super) enum SleepResult {
    Complete,
    Interrupted(Timespec),
    Unsupported,
}

/// Sleep against one monotonic deadline, checking native cancellation between
/// bounded kernel waits. This supports relative nanosleep and the relative
/// CLOCK_REALTIME/CLOCK_MONOTONIC clock_nanosleep forms, plus absolute
/// CLOCK_MONOTONIC. The ABI must leave other clocks and flags on their original
/// path: CPU clocks and clocks that advance through suspend are not equivalent.
///
/// ppoll atomically installs the entry mask for each slice. Signals remain
/// blocked between slices, so a handler cannot run in an internal gap and lose
/// the sleep's EINTR. Its kernel-written remainder precedes handler execution;
/// adding the unscheduled portion preserves nanosleep's remainder even when the
/// handler takes longer than the requested sleep. A deadline read after the
/// handler would incorrectly deduct that time.
///
/// STICKY_TIMEOUTS suppresses ppoll's remainder update. When a relative caller
/// needs a remainder, query the current personality while signals are blocked,
/// then retain the original syscall if the flag is set or the query is denied.
/// Never change the thread's personality or manufacture an estimated remainder.
/// Such fallback calls keep the existing pending-only cancellation behavior.
///
/// # Safety
/// The ABI supplies a valid owned timespec and selects one of the clock forms
/// above. `cancel` belongs to the calling registered native thread. This helper
/// restores the original mask before returning; the boundary must then test
/// cancellation before publishing an Interrupted remainder to caller memory.
pub(super) unsafe fn wait_sleep(
    request: &Timespec,
    absolute: bool,
    need_remainder: bool,
    cancel: CancellationWait,
) -> Result<SleepResult, c_int> {
    if request.tv_sec < 0
        || !(0..1_000_000_000).contains(&request.tv_nsec)
        || (request.tv_sec == 0 && request.tv_nsec == 0)
    {
        return Ok(SleepResult::Unsupported);
    }

    let mut guard = SignalMaskGuard::block_all()?;
    if !absolute && need_remainder {
        // SAFETY: this is a read-only personality query, with no pointers. It
        // changes neither the persona nor errno. Blocking handlers keeps this
        // per-task setting stable until ppoll has written the interruption
        // remainder; a handler can change it only after that kernel copy.
        let persona =
            unsafe { syscall::syscall1(libc::SYS_personality as usize, u32::MAX as usize) };
        if (-4095..0).contains(&(persona as isize)) || persona & STICKY_TIMEOUTS != 0 {
            return guard.restore().map(|()| SleepResult::Unsupported);
        }
    }
    // SAFETY: the original mask and request are owned, stationary values. The
    // wait uses no application descriptors or pointers and owns no resources.
    let result = unsafe { sleep_slices(request, absolute, need_remainder, &mut guard, cancel) };
    guard.restore().and(result)
}

/// Convert a nonnegative remaining duration, bounded by the caller's valid
/// timespec, without narrowing nanoseconds through a 64-bit total.
fn sleep_remainder(nanoseconds: i128) -> Timespec {
    let maximum = i128::from(i64::MAX) * NANOS_PER_SECOND + NANOS_PER_SECOND - 1;
    let nanoseconds = nanoseconds.clamp(0, maximum);
    Timespec {
        tv_sec: (nanoseconds / NANOS_PER_SECOND) as i64,
        tv_nsec: (nanoseconds % NANOS_PER_SECOND) as i64,
    }
}

// Like wait_slices, this frame owns no Drop state. Application signal handlers
// may unwind across the raw kernel wait; cancellation is delivered by the ABI
// only after the original signal mask has been restored by wait_sleep.
#[inline(never)]
unsafe fn sleep_slices(
    request: &Timespec,
    absolute: bool,
    need_remainder: bool,
    guard: &mut SignalMaskGuard,
    cancel: CancellationWait,
) -> Result<SleepResult, c_int> {
    let requested = i128::from(request.tv_sec) * NANOS_PER_SECOND + i128::from(request.tv_nsec);
    let deadline = if absolute {
        requested
    } else {
        monotonic_nanoseconds()? + requested
    };
    loop {
        let now = monotonic_nanoseconds()?;
        let remaining = (deadline - now).max(0);
        if cancel.pending() {
            return Ok(SleepResult::Interrupted(sleep_remainder(remaining)));
        }
        let (mut slice, final_slice) = next_slice(Some(deadline), now);
        let unscheduled = remaining - i128::from(slice.tv_nsec);
        let mask = core::ptr::from_ref(&guard.original).cast();
        // A user handler can exit the thread or unwind while ppoll has its
        // temporary mask installed. Its cleanup must retain that handler mask,
        // not restore the pre-sleep mask from a Drop during the unwind. Between
        // syscalls all signals are blocked; rearm immediately on normal return.
        guard.armed = false;
        // SAFETY: nfds is zero; the kernel sees only the owned mutable timeout
        // and the stable eight-byte copy of the calling thread's original mask.
        let result = unsafe {
            syscall::sys_ppoll(
                core::ptr::null_mut(),
                0,
                core::ptr::from_mut(&mut slice).cast::<u8>().cast_const(),
                mask,
                KERNEL_SIGSET_BYTES,
            )
        };
        guard.armed = true;
        match result {
            Ok(0) if !final_slice => {}
            Ok(_) => return Ok(SleepResult::Complete),
            Err(libc::EINTR) => {
                let remainder = if !absolute && need_remainder {
                    let in_kernel =
                        i128::from(slice.tv_sec) * NANOS_PER_SECOND + i128::from(slice.tv_nsec);
                    sleep_remainder(unscheduled + in_kernel)
                } else {
                    Timespec::default()
                };
                return Ok(SleepResult::Interrupted(remainder));
            }
            Err(error) => return Err(error),
        }
    }
}

/// Child waits use WNOHANG probes without changing the caller's child selector
/// or event options. An acquired event belongs to the caller, even when a
/// cancellation request races its acquisition.
#[derive(Clone, Copy)]
pub(super) enum ChildWait {
    Wait4 {
        pid: c_int,
        status: *mut c_int,
        options: c_int,
        usage: *mut u8,
    },
    WaitId {
        idtype: c_int,
        id: u32,
        info: *mut u8,
        options: c_int,
    },
}

impl ChildWait {
    pub(super) fn supports_slices(self) -> bool {
        match self {
            // A single wait snapshots the current process group. Repeating
            // pid=0 probes could follow another thread's later setpgid call.
            Self::Wait4 { pid, options, .. } => pid != 0 && options & libc::WNOHANG == 0,
            // P_PIDFD is 3 on Linux. Its descriptor may be O_NONBLOCK (which
            // requires EAGAIN, not an empty WNOHANG result), and a concurrent
            // close/reuse must not redirect an ongoing wait to another child.
            // Keep that descriptor-identity contract on the original syscall.
            Self::WaitId {
                idtype,
                id,
                options,
                ..
            } => {
                matches!(idtype, 0..=2)
                    && !(idtype == libc::P_PGID as c_int && id == 0)
                    && options & libc::WNOHANG == 0
            }
        }
    }

    /// Issue the original operation. Hosted/disabled/internal and unsupported
    /// native paths retain the exact original syscall and pointer semantics.
    pub(super) unsafe fn blocking(self) -> Result<c_int, c_int> {
        match self {
            Self::Wait4 {
                pid,
                status,
                options,
                usage,
            } => unsafe { syscall::sys_wait4(pid, status, options, usage) },
            Self::WaitId {
                idtype,
                id,
                info,
                options,
            } => unsafe {
                syscall::sys_waitid(idtype, id, info, options, core::ptr::null_mut()).map(|()| 0)
            },
        }
    }

    unsafe fn probe(self) -> Result<Option<c_int>, c_int> {
        match self {
            Self::Wait4 {
                pid,
                status,
                options,
                usage,
            } => {
                // A zero-result wait4 probe leaves both caller outputs alone.
                let pid =
                    unsafe { syscall::sys_wait4(pid, status, options | libc::WNOHANG, usage) }?;
                Ok((pid != 0).then_some(pid))
            }
            Self::WaitId {
                idtype,
                id,
                info,
                options,
            } => {
                // Unlike wait4, waitid writes six zero fields on interruption,
                // no event and even argument errors. Stage its exact output,
                // then publish it before a handler or cancellation can run.
                let mut event = syscall::WaitSigInfo::default();
                let result = unsafe {
                    syscall::sys_waitid_info(idtype, id, &mut event, options | libc::WNOHANG)
                };
                if !info.is_null() {
                    // Linux writes exactly these six 32-bit fields; the
                    // alignment padding and unused union tail stay untouched.
                    // Preserve that byte contract, including unaligned output,
                    // and report EFAULT through the kernel-backed copier.
                    let source = core::ptr::from_ref(&event).cast::<u8>();
                    unsafe {
                        copy_user_bytes(source, info, 12)?;
                        copy_user_bytes(source.add(16), info.add(16), 12)?;
                    }
                }
                result?;
                Ok((event.child_pid() != 0).then_some(0))
            }
        }
    }
}

pub(super) enum ChildWaitResult {
    Ready(c_int),
    Cancel,
    Unsupported,
}

/// A receive can probe without changing the socket's shared file status flags.
/// Never follow readiness with a blocking receive: another receiver may consume
/// the data first. MSG_DONTWAIT makes that race an ordinary retry instead.
#[derive(Clone, Copy)]
pub(super) enum Receive {
    Read {
        fd: c_int,
        buffer: *mut u8,
        length: usize,
    },
    From {
        fd: c_int,
        buffer: *mut u8,
        length: usize,
        flags: c_int,
        address: *mut u8,
        address_length: *mut u32,
    },
    Message {
        fd: c_int,
        message: *mut u8,
        flags: c_int,
    },
}

impl Receive {
    fn fd(self) -> c_int {
        match self {
            Self::Read { fd, .. } | Self::From { fd, .. } | Self::Message { fd, .. } => fd,
        }
    }

    fn flags(self) -> c_int {
        match self {
            Self::Read { .. } => 0,
            Self::From { flags, .. } | Self::Message { flags, .. } => flags,
        }
    }

    fn supports_slices(self) -> bool {
        // A zero-length read keeps the original syscall, including descriptor
        // validation and datagram behavior. Only ordinary stream sockets admit
        // replacing read with a per-call nonblocking receive below.
        if matches!(self, Self::Read { length: 0, .. }) {
            return false;
        }
        // WAITALL, urgent/error-queue data, caller-requested nonblocking I/O,
        // and unfamiliar protocol flags keep the original kernel operation.
        // recvmsg's CLOEXEC changes only acquired descriptor flags, not waiting
        // behavior. Keep it on every probe so SCM_RIGHTS publication stays atomic.
        let supported_flags = libc::MSG_PEEK
            | libc::MSG_TRUNC
            | if matches!(self, Self::Message { .. }) {
                libc::MSG_CMSG_CLOEXEC
            } else {
                0
            };
        if self.flags() & !supported_flags != 0 {
            return false;
        }
        let fd = self.fd();
        // SAFETY: F_GETFL has no pointer argument and does not mutate the open
        // file description. A failed query must not replace recv's own error.
        let Ok(status) = (unsafe { syscall::sys_fcntl(fd, libc::F_GETFL, 0) }) else {
            return false;
        };
        if status & libc::O_NONBLOCK != 0 {
            return false;
        }
        let socket_type = socket_integer_option(fd, libc::SO_TYPE);
        let supported_socket = if matches!(self, Self::Read { .. }) {
            socket_type == Some(libc::SOCK_STREAM)
        } else {
            matches!(
                socket_type,
                Some(libc::SOCK_STREAM | libc::SOCK_DGRAM | libc::SOCK_SEQPACKET)
            )
        };
        if !supported_socket
            || !matches!(
                socket_integer_option(fd, libc::SO_DOMAIN),
                Some(libc::AF_UNIX | libc::AF_INET | libc::AF_INET6)
            )
            || socket_integer_option(fd, libc::SO_RCVLOWAT) != Some(1)
        {
            return false;
        }
        let mut timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut size = core::mem::size_of::<libc::timeval>() as u32;
        // SAFETY: both outputs are owned, aligned kernel ABI storage. Only a
        // socket with no receive timeout is interchangeable with indefinite
        // readiness waits; finite timeouts retain their exact kernel contract.
        unsafe {
            syscall::sys_getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                core::ptr::from_mut(&mut timeout).cast(),
                &mut size,
            )
        }
        .is_ok()
            && size as usize == core::mem::size_of::<libc::timeval>()
            && timeout.tv_sec == 0
            && timeout.tv_usec == 0
    }

    unsafe fn probe(self) -> Result<isize, c_int> {
        // SAFETY: retain the original buffer/header graph through the kernel
        // call; no payload, address or control metadata is copied in Rust.
        unsafe { self.call(libc::MSG_DONTWAIT) }
    }

    pub(super) unsafe fn blocking(self) -> Result<isize, c_int> {
        // SAFETY: the originating entry keeps all caller or prepared storage live.
        unsafe { self.call(0) }
    }

    unsafe fn call(self, additional_flags: c_int) -> Result<isize, c_int> {
        // SAFETY: the public entry retains all original pointer arguments.
        // The kernel validates them and owns payload/address/control publication.
        // A successful recvmsg may transfer SCM_RIGHTS ownership, so the caller
        // must publish its result without retrying or acting on a racing cancel.
        match self {
            Self::Read { fd, buffer, length } if additional_flags == 0 => {
                // Keep read itself for disabled, hosted, internal and unsupported
                // callers; recvfrom is only the admitted native stream probe.
                unsafe { syscall::sys_read(fd, buffer, length) }.map(|read| read as isize)
            }
            Self::Read { fd, buffer, length } => unsafe {
                syscall::sys_recvfrom(
                    fd,
                    buffer,
                    length,
                    additional_flags,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            },
            Self::From {
                fd,
                buffer,
                length,
                flags,
                address,
                address_length,
            } => unsafe {
                syscall::sys_recvfrom(
                    fd,
                    buffer,
                    length,
                    flags | additional_flags,
                    address,
                    address_length,
                )
            },
            Self::Message { fd, message, flags } => unsafe {
                syscall::sys_recvmsg(fd, message, flags | additional_flags)
            },
        }
    }
}

fn socket_integer_option(fd: c_int, option: c_int) -> Option<c_int> {
    let mut value = 0;
    let mut size = core::mem::size_of::<c_int>() as u32;
    // SAFETY: the query writes only to live integer/length output storage.
    unsafe {
        syscall::sys_getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            core::ptr::from_mut(&mut value).cast(),
            &mut size,
        )
    }
    .ok()?;
    (size as usize == core::mem::size_of::<c_int>()).then_some(value)
}

pub(super) enum ReceiveResult {
    Ready(isize),
    Cancel,
    Unsupported,
}

/// A send uses per-call nonblocking probes, never F_SETFL: changing the open
/// file description would also change another thread's socket operations.
#[derive(Clone, Copy)]
pub(super) struct SendTo {
    pub fd: c_int,
    pub buffer: *const u8,
    pub length: usize,
    pub flags: c_int,
    pub address: *const u8,
    pub address_length: usize,
}

#[derive(Clone, Copy)]
pub(super) enum Send {
    To(SendTo),
    Message {
        fd: c_int,
        message: *const u8,
        flags: c_int,
    },
}

impl Send {
    pub(super) unsafe fn blocking(self) -> Result<isize, c_int> {
        // SAFETY: the public ABI keeps its caller/prepared pointer graph live;
        // the kernel imports every descriptor and validates all payload bytes.
        match self {
            Self::To(operation) => unsafe {
                syscall::sys_sendto(
                    operation.fd,
                    operation.buffer,
                    operation.length,
                    operation.flags,
                    operation.address,
                    operation.address_length,
                )
            },
            Self::Message { fd, message, flags } => unsafe {
                syscall::sys_sendmsg(fd, message, flags)
            },
        }
    }
}

/// Both forms own their descriptor geometry while the native wait is sliced.
/// Payload pointers still belong to the caller and are checked only by Linux.
trait SendOperation {
    fn fd(&self) -> c_int;
    fn flags(&self) -> c_int;
    fn length(&self) -> usize;

    fn supports_slices(&self) -> bool {
        // Preserve record/cork/urgent/fast-open semantics and Linux's clipping
        // of enormous iov lengths in the original single syscall. The limit
        // below is no larger than MAX_RW_COUNT on either 4 KiB or 64 KiB pages.
        if self.flags() & !libc::MSG_NOSIGNAL != 0 || self.length() > 0x7fff_0000 {
            return false;
        }
        let fd = self.fd();
        // SAFETY: F_GETFL has no pointer argument and does not mutate the fd.
        let Ok(status) = (unsafe { syscall::sys_fcntl(fd, libc::F_GETFL, 0) }) else {
            return false;
        };
        if status & libc::O_NONBLOCK != 0 {
            return false;
        }
        let socket_type = socket_integer_option(fd, libc::SO_TYPE);
        let domain = socket_integer_option(fd, libc::SO_DOMAIN);
        let protocol = socket_integer_option(fd, libc::SO_PROTOCOL);
        if !matches!(
            (domain, socket_type, protocol),
            (
                Some(libc::AF_UNIX),
                Some(libc::SOCK_STREAM | libc::SOCK_DGRAM | libc::SOCK_SEQPACKET),
                Some(0)
            ) | (
                Some(libc::AF_INET | libc::AF_INET6),
                Some(libc::SOCK_STREAM),
                Some(libc::IPPROTO_TCP)
            ) | (
                Some(libc::AF_INET | libc::AF_INET6),
                Some(libc::SOCK_DGRAM),
                Some(libc::IPPROTO_UDP)
            )
        ) {
            return false;
        }
        let mut timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut size = core::mem::size_of::<libc::timeval>() as u32;
        // SAFETY: the query writes only to aligned, owned kernel ABI storage.
        // Finite send deadlines retain their original kernel implementation.
        unsafe {
            syscall::sys_getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                core::ptr::from_mut(&mut timeout).cast(),
                &mut size,
            )
        }
        .is_ok()
            && size as usize == core::mem::size_of::<libc::timeval>()
            && timeout.tv_sec == 0
            && timeout.tv_usec == 0
    }

    unsafe fn probe(&mut self, sent: usize) -> Result<isize, c_int>;
}

impl SendOperation for SendTo {
    fn fd(&self) -> c_int {
        self.fd
    }

    fn flags(&self) -> c_int {
        self.flags
    }

    fn length(&self) -> usize {
        self.length
    }

    unsafe fn probe(&mut self, sent: usize) -> Result<isize, c_int> {
        // A blocking stream send returns its accepted prefix on a later error,
        // without raising SIGPIPE for that error. Subsequent probes must not
        // manufacture SIGPIPE merely because that prefix used a separate call.
        let flags =
            self.flags | libc::MSG_DONTWAIT | if sent == 0 { 0 } else { libc::MSG_NOSIGNAL };
        // SAFETY: sent is bounded by length and counts bytes accepted by prior
        // kernel calls. wrapping_add keeps inaccessible caller pointers under
        // kernel validation rather than forming a Rust slice/reference to them.
        unsafe {
            syscall::sys_sendto(
                self.fd,
                self.buffer.wrapping_add(sent),
                self.length - sent,
                flags,
                self.address,
                self.address_length,
            )
        }
    }
}

/// A complete descriptor import with eight inline entries and raw mmap storage
/// for larger vectors, avoiding large native-thread stack frames, shared TLS
/// scratch and allocator reentry. Neither the caller's header nor its iovec
/// array is modified while consuming an accepted stream prefix.
struct SendMessage {
    fd: c_int,
    flags: c_int,
    header: libc::msghdr,
    vectors: crate::io_abi::iov_snapshot::PreparedIovecs,
    count: usize,
    first: usize,
    advanced: usize,
    length: usize,
}

impl SendMessage {
    fn import(fd: c_int, message: *const u8, flags: c_int) -> Option<Self> {
        // SAFETY: all-zero is valid for the scalar and raw-pointer fields of
        // msghdr. It is initialized before the kernel copies caller bytes.
        let mut header: libc::msghdr = unsafe { core::mem::zeroed() };
        // SAFETY: the destination is exclusively owned initialized storage.
        // The caller source is fault-checked, including unaligned headers.
        unsafe {
            copy_user_bytes(
                message,
                core::ptr::from_mut(&mut header).cast(),
                core::mem::size_of::<libc::msghdr>(),
            )
        }
        .ok()?;
        if header.msg_iovlen > crate::io_abi::iov_snapshot::MAX_IOVECS {
            return None;
        }
        // The established importer uses inline or privately mapped storage,
        // never malloc. Rejecting an unsupported/invalid graph here retains the
        // original syscall's error ordering; no payload has been transmitted.
        let vectors = crate::io_abi::iov_snapshot::PreparedIovecs::prepare_unsigned(
            header.msg_iov,
            header.msg_iovlen,
            true,
        )
        .ok()?;
        if vectors.entries().len() != header.msg_iovlen {
            return None;
        }
        let mut operation = Self {
            fd,
            flags,
            header,
            vectors,
            count: header.msg_iovlen,
            first: 0,
            advanced: 0,
            length: 0,
        };
        for entry in operation.vectors.entries() {
            operation.length = operation.length.checked_add(entry.iov_len)?;
        }
        Some(operation)
    }
}

impl SendOperation for SendMessage {
    fn fd(&self) -> c_int {
        self.fd
    }

    fn flags(&self) -> c_int {
        self.flags
    }

    fn length(&self) -> usize {
        self.length
    }

    unsafe fn probe(&mut self, sent: usize) -> Result<isize, c_int> {
        let mut advance = sent - self.advanced;
        let vectors = self.vectors.entries_mut();
        if advance != 0 {
            // Submit the complete imported graph before the first byte is
            // accepted, including zero-length entries: their kernel address
            // validation must not be elided by a premature cursor advance.
            while self.first < self.count && advance >= vectors[self.first].iov_len {
                advance -= vectors[self.first].iov_len;
                self.first += 1;
            }
            if advance != 0 {
                let first = &mut vectors[self.first];
                first.iov_base = first.iov_base.cast::<u8>().wrapping_add(advance).cast();
                first.iov_len -= advance;
            }
        }
        self.advanced = sent;
        self.header.msg_iov = self.vectors.as_ptr().cast_mut().wrapping_add(self.first);
        self.header.msg_iovlen = self.count - self.first;
        if sent != 0 {
            // Ancillary data belongs to the first accepted message fragment.
            // Replaying SCM_RIGHTS on a stream continuation would install a
            // second set of descriptors at the receiver, even with exact bytes.
            self.header.msg_control = core::ptr::null_mut();
            self.header.msg_controllen = 0;
        }
        let flags =
            self.flags | libc::MSG_DONTWAIT | if sent == 0 { 0 } else { libc::MSG_NOSIGNAL };
        // SAFETY: this header and imported vector remain stationary across the
        // syscall. All payload/name/control pointers are still kernel-validated;
        // only the privately owned iovec geometry is adjusted in Rust.
        unsafe { syscall::sys_sendmsg(self.fd, core::ptr::from_ref(&self.header).cast(), flags) }
    }
}

pub(super) enum SendResult {
    Ready(isize),
    Cancel,
    Unsupported,
}

/// Send ordinary stream or atomic-message data with bounded cancellation.
/// Stream prefixes are accumulated until the original request completes. A
/// later cancellation/error returns the already accepted prefix, as a single
/// interrupted blocking send does; it must never replay or hide those bytes.
/// Caught signals and nondefault flags/timeouts retain their kernel contracts.
/// As with receives, concurrent installation and delivery of a new handler
/// inside a slice is outside this cooperative path's supported scope.
///
/// # Safety
/// The ABI supplies its original send arguments and the enabled descriptor for
/// this native thread. The signal check inspects actual kernel dispositions.
pub(super) unsafe fn wait_send(
    operation: Send,
    cancel: CancellationWait,
    supports_handlers: fn(u64) -> bool,
) -> Result<SendResult, c_int> {
    // SAFETY: both arms retain the original pointers for the complete native
    // operation. Any owned message mapping is dropped before this returns.
    match operation {
        Send::To(operation) => unsafe { wait_send_operation(operation, cancel, supports_handlers) },
        Send::Message { fd, message, flags } => unsafe {
            wait_send_message(fd, message, flags, cancel, supports_handlers)
        },
    }
}

#[inline(never)]
unsafe fn wait_send_message(
    fd: c_int,
    message: *const u8,
    flags: c_int,
    cancel: CancellationWait,
    supports_handlers: fn(u64) -> bool,
) -> Result<SendResult, c_int> {
    let Some(operation) = SendMessage::import(fd, message, flags) else {
        return Ok(SendResult::Unsupported);
    };
    // SAFETY: the imported descriptor graph remains owned by this native path;
    // on an unsupported contract no bytes or ancillary data were transmitted.
    unsafe { wait_send_operation(operation, cancel, supports_handlers) }
}

unsafe fn wait_send_operation(
    mut operation: impl SendOperation,
    cancel: CancellationWait,
    supports_handlers: fn(u64) -> bool,
) -> Result<SendResult, c_int> {
    if !operation.supports_slices() {
        return Ok(SendResult::Unsupported);
    }
    let Ok(mut mask) = SignalMaskGuard::block_all() else {
        return Ok(SendResult::Unsupported);
    };
    // SAFETY: the original arguments and mask remain live across every probe;
    // cancellation unwinds only after this helper restores the entry mask.
    let result = unsafe { send_slices(&mut operation, cancel, supports_handlers, &mut mask) };
    let restored = mask.restore();
    match result {
        // Even an adapter-only restoration error cannot erase a committed
        // send: reporting failure would invite the caller to duplicate bytes
        // (or an accepted zero-length datagram) by retrying the operation.
        Ok(SendResult::Ready(sent)) => Ok(SendResult::Ready(sent)),
        other => restored.and(other),
    }
}

#[inline(never)]
unsafe fn send_slices(
    operation: &mut impl SendOperation,
    cancel: CancellationWait,
    supports_handlers: fn(u64) -> bool,
    mask: &mut SignalMaskGuard,
) -> Result<SendResult, c_int> {
    let mut sent = 0;
    loop {
        if cancel.pending() {
            return Ok(if sent == 0 {
                SendResult::Cancel
            } else {
                SendResult::Ready(sent as isize)
            });
        }
        if !supports_handlers(mask.original) || !operation.supports_slices() {
            return Ok(if sent == 0 {
                SendResult::Unsupported
            } else {
                SendResult::Ready(sent as isize)
            });
        }
        // Datagram/SEQPACKET sends are atomic; only stream probes can accept a
        // prefix. Do not turn a temporary lack of space into a short success.
        match unsafe { operation.probe(sent) } {
            Ok(written) => {
                sent += written as usize;
                if written == 0 || sent == operation.length() {
                    return Ok(SendResult::Ready(sent as isize));
                }
                continue;
            }
            Err(libc::EAGAIN) => {}
            Err(_) if sent != 0 => return Ok(SendResult::Ready(sent as isize)),
            Err(error) => return Err(error),
        }
        let mut interest = libc::pollfd {
            fd: operation.fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let mut slice = Timespec {
            tv_sec: 0,
            tv_nsec: SLICE_NS,
        };
        // A concurrently installed handler may unwind; do not restore its
        // handler mask during that unwind. Ordinary return reblocks signals.
        mask.armed = false;
        let result = unsafe {
            syscall::sys_ppoll(
                core::ptr::from_mut(&mut interest).cast(),
                1,
                core::ptr::from_mut(&mut slice).cast(),
                core::ptr::from_ref(&mask.original).cast(),
                KERNEL_SIGSET_BYTES,
            )
        };
        mask.armed = true;
        if let Err(error) = result {
            if sent != 0 {
                return Ok(SendResult::Ready(sent as isize));
            }
            if cancel.pending() {
                return Ok(SendResult::Cancel);
            }
            if error == libc::EINTR {
                return Err(error);
            }
            // A missing/blocked adapter syscall must not replace sendto's own
            // behavior. Only a zero-progress operation may use the raw fallback.
            return Ok(SendResult::Unsupported);
        }
    }
}

/// Receive ordinary socket data with bounded native cancellation, leaving every
/// successful receive committed even if a cancellation request races completion.
/// Nondefault timeout/low-water/flag contracts and deliverable caught signals
/// keep the raw receive. In particular, ppoll must not replace recv's SA_RESTART
/// behavior. As for child waits, concurrent installation and delivery of a new
/// handler inside a slice is outside this cooperative path's supported scope.
///
/// # Safety
/// The ABI supplies its original receive arguments and an enabled cancellation
/// descriptor belonging to the calling native thread. `supports_handlers`
/// inspects actual kernel dispositions while the original mask is blocked.
pub(super) unsafe fn wait_receive(
    operation: Receive,
    cancel: CancellationWait,
    supports_handlers: fn(u64) -> bool,
) -> Result<ReceiveResult, c_int> {
    if !operation.supports_slices() {
        return Ok(ReceiveResult::Unsupported);
    }
    let Ok(mut mask) = SignalMaskGuard::block_all() else {
        // An unavailable adapter syscall must not replace the original receive
        // with a new error, and no caller output or descriptor has changed.
        return Ok(ReceiveResult::Unsupported);
    };
    // SAFETY: operation's pointers and the owned mask remain live across every
    // nonblocking probe and bounded wait; no cancellation unwinds in this helper.
    let result = unsafe { receive_slices(operation, cancel, supports_handlers, &mut mask) };
    let restored = mask.restore();
    match result {
        // A successful receive has already consumed bytes and may have installed
        // descriptors. An adapter-only error must not hide that ownership transfer.
        Ok(ReceiveResult::Ready(received)) => Ok(ReceiveResult::Ready(received)),
        other => restored.and(other),
    }
}

#[inline(never)]
unsafe fn receive_slices(
    operation: Receive,
    cancel: CancellationWait,
    supports_handlers: fn(u64) -> bool,
    mask: &mut SignalMaskGuard,
) -> Result<ReceiveResult, c_int> {
    loop {
        if cancel.pending() {
            return Ok(ReceiveResult::Cancel);
        }
        if !supports_handlers(mask.original) || !operation.supports_slices() {
            return Ok(ReceiveResult::Unsupported);
        }
        // A successful probe may consume a datagram or stream bytes. Never
        // discard it for a request racing the kernel's completed operation.
        match unsafe { operation.probe() } {
            Ok(received) => return Ok(ReceiveResult::Ready(received)),
            Err(libc::EAGAIN) => {}
            // A sandbox may permit read but deny the adapter's recvfrom. No
            // bytes were acquired; preserve the caller's original operation.
            Err(libc::ENOSYS | libc::EPERM | libc::EACCES)
                if matches!(operation, Receive::Read { .. }) =>
            {
                return Ok(ReceiveResult::Unsupported);
            }
            Err(error) => return Err(error),
        }
        let mut interest = libc::pollfd {
            fd: operation.fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let mut slice = Timespec {
            tv_sec: 0,
            tv_nsec: SLICE_NS,
        };
        // A newly installed application handler may unwind. As in child_slices,
        // do not restore its signal mask during that unwind. Ordinary return
        // reinstates the blocked mask before inspecting cancellation or data.
        mask.armed = false;
        let result = unsafe {
            syscall::sys_ppoll(
                core::ptr::from_mut(&mut interest).cast(),
                1,
                core::ptr::from_mut(&mut slice).cast(),
                core::ptr::from_ref(&mask.original).cast(),
                KERNEL_SIGSET_BYTES,
            )
        };
        mask.armed = true;
        if cancel.pending() {
            return Ok(ReceiveResult::Cancel);
        }
        match result {
            Ok(_) => {}
            Err(libc::EINTR) => return Err(libc::EINTR),
            // Seccomp/kernel support for ppoll need not match recvfrom. No data
            // was acquired, so preserve the original syscall on adapter errors.
            Err(_) => return Ok(ReceiveResult::Unsupported),
        }
    }
}

/// Check cancellation every 50 ms when no caught signal is deliverable. With
/// an unblocked handler, retain the original syscall: ppoll always interrupts,
/// but child waits honor SA_RESTART, including nested signal deliveries.
///
/// Signal dispositions must stay free of deliverable caught handlers while a
/// slice is in progress. Recheck between slices and fall back if that changes;
/// installing and delivering a new handler concurrently within one slice is
/// outside this cooperative path's supported scope. A future native syscall
/// interruption mechanism is needed to remove this restriction atomically.
///
/// # Safety
/// The ABI supplies an enabled native cancellation descriptor belonging to the
/// caller, and valid raw wait arguments. `supports_handlers` inspects the actual
/// unblocked kernel handlers while signals are blocked without changing them.
pub(super) unsafe fn wait_child(
    operation: ChildWait,
    cancel: CancellationWait,
    supports_handlers: fn(u64) -> bool,
) -> Result<ChildWaitResult, c_int> {
    let mut mask = SignalMaskGuard::block_all()?;
    let result = unsafe { child_slices(operation, cancel, supports_handlers, &mut mask) };
    mask.restore().and(result)
}

// This syscall frame owns no Drop state. Signal handlers can unwind through
// it with their current signal mask; the parent disarms restoration before
// ppoll and rearms it only after a normal return with all signals blocked.
#[inline(never)]
unsafe fn child_slices(
    operation: ChildWait,
    cancel: CancellationWait,
    supports_handlers: fn(u64) -> bool,
    mask: &mut SignalMaskGuard,
) -> Result<ChildWaitResult, c_int> {
    loop {
        if cancel.pending() {
            return Ok(ChildWaitResult::Cancel);
        }
        if !supports_handlers(mask.original) {
            return Ok(ChildWaitResult::Unsupported);
        }
        if let Some(result) = unsafe { operation.probe() }? {
            return Ok(ChildWaitResult::Ready(result));
        }
        let mut slice = Timespec {
            tv_sec: 0,
            tv_nsec: SLICE_NS,
        };
        mask.armed = false;
        let result = unsafe {
            syscall::sys_ppoll(
                core::ptr::null_mut(),
                0,
                core::ptr::from_mut(&mut slice).cast(),
                core::ptr::from_ref(&mask.original).cast(),
                KERNEL_SIGSET_BYTES,
            )
        };
        mask.armed = true;
        if cancel.pending() && matches!(result, Ok(_) | Err(libc::EINTR)) {
            return Ok(ChildWaitResult::Cancel);
        }
        match result {
            Ok(_) => {}
            Err(libc::EINTR) => {
                // A child may become waitable along with SIGCHLD. Just as a
                // kernel wait, prefer an available event over interruption.
                return match unsafe { operation.probe() }? {
                    Some(result) => Ok(ChildWaitResult::Ready(result)),
                    None => Err(libc::EINTR),
                };
            }
            Err(error) => return Err(error),
        }
    }
}

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
            CancellationMask::Wait,
        )
    }
}

/// Suspend for signal delivery without descriptors or a deadline. Restore the
/// original mask before cancellation cleanup, as observed with GNU sigsuspend.
/// Keep this explicit without changing the existing descriptor-wait policy.
///
/// # Safety
/// The mask and callback have the same requirements as [`wait`]. No Rust
/// reference is formed to caller signal-set storage; the kernel validates it.
pub(super) unsafe fn wait_signal(
    mask: *const u8,
    cancel: CancellationWait,
    on_cancel: unsafe extern "C-unwind" fn(),
) -> Result<(), c_int> {
    // SAFETY: the caller retains the mask and owned cancellation descriptor.
    unsafe {
        wait_operation(
            Operation::Poll {
                fds: core::ptr::null_mut(),
                nfds: 0,
            },
            core::ptr::null(),
            mask,
            cancel,
            on_cancel,
            CancellationMask::Original,
        )
        .map(|_| ())
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
            CancellationMask::Wait,
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
            CancellationMask::Wait,
        )
    }
}

enum CancellationMask {
    Wait,
    Original,
}

unsafe fn wait_operation(
    operation: Operation,
    timeout: *const u8,
    mask: *const u8,
    cancel: CancellationWait,
    on_cancel: unsafe extern "C-unwind" fn(),
    cancellation_mask: CancellationMask,
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
            // Poll/epoll install the temporary mask directly from the blocked
            // state. Signal suspension instead restores the original mask,
            // including any handlers that must run before its cleanup.
            let cleanup_mask = match cancellation_mask {
                CancellationMask::Wait => mask,
                CancellationMask::Original => core::ptr::null(),
            };
            unsafe { guard.deliver_cancel(cleanup_mask, on_cancel) }.and(Err(libc::EINTR))
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
    fn sleep_remainders_keep_subsecond_precision_and_full_time_t_range() {
        let maximum = i128::from(i64::MAX) * NANOS_PER_SECOND + 999_999_999;
        for (nanoseconds, seconds, fraction) in [
            (-1, 0, 0),
            (0, 0, 0),
            (1, 0, 1),
            (999_999_999, 0, 999_999_999),
            (1_000_000_001, 1, 1),
            (maximum, i64::MAX, 999_999_999),
            (i128::MAX, i64::MAX, 999_999_999),
        ] {
            let remainder = sleep_remainder(nanoseconds);
            assert_eq!(remainder.tv_sec, seconds);
            assert_eq!(remainder.tv_nsec, fraction);
        }
    }

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
