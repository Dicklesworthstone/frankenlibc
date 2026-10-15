//! Completion ownership for POSIX AIO. No control-block pointer survives its
//! final status publication. Batch accounting owns counters, never a borrowed
//! list or a pointer to an already completed/reusable request.

use std::ffi::{c_int, c_void};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use frankenlibc_core::syscall as raw;

pub(super) static EPOCH: AtomicU32 = AtomicU32::new(0);

type Callback = unsafe extern "C-unwind" fn(libc::sigval);

#[derive(Clone, Copy)]
pub(super) enum Notice {
    None,
    Signal { signo: c_int, value: usize, pid: c_int, uid: u32 },
    Thread { callback: Callback, value: usize },
}

impl Notice {
    /// Snapshot the event; the attribute pointer is consumed by pthread_create
    /// during submission, not retained until I/O completion.
    pub(super) unsafe fn read(event: *const libc::sigevent)
        -> Result<(Self, *const libc::pthread_attr_t), c_int>
    {
        if event.is_null() {
            return Ok((Self::None, std::ptr::null()));
        }
        // SAFETY: the caller keeps this sigevent live through submission.
        let event = unsafe { &*event };
        let value = event.sigev_value.sival_ptr as usize;
        match event.sigev_notify {
            libc::SIGEV_NONE => Ok((Self::None, std::ptr::null())),
            libc::SIGEV_SIGNAL if (0..=64).contains(&event.sigev_signo) => Ok((
                Self::Signal { signo: event.sigev_signo, value,
                    pid: raw::sys_getpid(), uid: raw::sys_getuid() },
                std::ptr::null(),
            )),
            libc::SIGEV_THREAD => {
                // Linux LP64 sigevent: sigval at 0, signo at 8, notify at 12,
                // and the thread union (function, attributes) at 16. libc's
                // Rust type exposes only the overlapping thread-id member.
                // SAFETY: both supported Linux LP64 ABIs have this layout;
                // the external C fixture asserts it using platform headers.
                let bytes = (event as *const libc::sigevent).cast::<u8>();
                let function = unsafe { bytes.add(16).cast::<usize>().read() };
                let attributes = unsafe {
                    bytes.add(24).cast::<*const libc::pthread_attr_t>().read()
                };
                if function == 0 {
                    return Err(libc::EINVAL);
                }
                // SAFETY: POSIX supplies a C function with this signature. The
                // unwind ABI permits pthread_exit and cancellation in callbacks.
                let callback = unsafe { std::mem::transmute::<usize, Callback>(function) };
                Ok((Self::Thread { callback, value }, attributes))
            }
            _ => Err(libc::EINVAL),
        }
    }

    pub(super) unsafe fn deliver(self) {
        match self {
            Self::None => {}
            Self::Thread { callback, value } => {
                // SAFETY: this invocation is in its own detached worker, after
                // all request/batch ownership has been released.
                unsafe { callback(libc::sigval { sival_ptr: value as *mut c_void }) };
            }
            Self::Signal { signo, value, pid, uid } => {
                // Linux siginfo_t's union begins at offset 16 on LP64. Do not
                // confuse the header padding at 12 with the si_pid field.
                #[repr(C)]
                struct QueuedInfo {
                    signo: c_int,
                    error: c_int,
                    code: c_int,
                    padding: c_int,
                    pid: c_int,
                    uid: u32,
                    value: usize,
                    reserved: [u8; 96],
                }
                const { assert!(std::mem::size_of::<QueuedInfo>() == 128); }
                let info = QueuedInfo { signo, error: 0, code: libc::SI_ASYNCIO,
                    padding: 0, pid, uid, value, reserved: [0; 96] };
                // SAFETY: the kernel copies a complete initialized siginfo.
                let _ = unsafe { raw::sys_rt_sigqueueinfo(pid, signo,
                    (&info as *const QueuedInfo).cast::<u8>()) };
            }
        }
    }
}

pub(super) fn wake(word: &AtomicU32) {
    // SAFETY: callers retain the word for the duration of the kernel operation.
    let _ = unsafe { raw::sys_futex(word as *const AtomicU32 as *const u32,
        libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG, c_int::MAX as u32, 0, 0, 0) };
}

pub(super) fn publish() {
    EPOCH.fetch_add(1, Ordering::Release);
    wake(&EPOCH);
}

/// One interruptible kernel wait. The exported cancellation-point frame owns
/// the cancellation window, rather than hiding the application caller here.
pub(super) fn wait(expected: u32, timeout: *const libc::timespec) -> Result<(), c_int> {
    // SAFETY: EPOCH is static and timeout is null or a live caller stack value.
    unsafe { raw::sys_futex(&EPOCH as *const AtomicU32 as *const u32,
        libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG, expected, timeout as usize, 0, 0) }
        .map(|_| ())
}

/// Use pthread's start ABI, not std::thread's catch_unwind wrapper: a POSIX
/// notification callback may exit or be canceled without returning to Rust.
pub(super) unsafe fn spawn(
    entry: unsafe extern "C-unwind" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
    attributes: *const libc::pthread_attr_t,
) -> Result<(), c_int> {
    // SAFETY: C and C-unwind have the same machine ABI. The pointed-to entry
    // retains its unwind-capable frame even though pthread's slot is plain C.
    let entry = unsafe { std::mem::transmute::<
        unsafe extern "C-unwind" fn(*mut c_void) -> *mut c_void,
        unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    >(entry) };
    let mut thread = 0;
    // SAFETY: attributes are read only during this call; the new thread owns
    // arg after successful creation, otherwise ownership stays with the caller.
    let rc = unsafe { crate::pthread_abi::pthread_create(
        &mut thread, attributes, Some(entry), arg) };
    if rc == 0 { Ok(()) } else { Err(rc) }
}

pub(super) fn detach_current() {
    let thread = crate::pthread_abi::native_pthread_self();
    // SAFETY: this worker has no external joiner. Attributes may already have
    // made it detached; in that case pthread_detach's EINVAL is harmless.
    let _ = unsafe { crate::pthread_abi::pthread_detach(thread) };
}

pub(super) struct Group {
    remaining: AtomicU32,
    signal: Notice,
}

impl Group {
    /// Hold one submission reservation so fast workers cannot notify before
    /// the entire list has been considered. A thread event gets its own waiter
    /// now, consuming the supplied attributes while they are still live.
    pub(super) unsafe fn new(event: *const libc::sigevent) -> Result<Arc<Self>, c_int> {
        let (notice, attributes) = unsafe { Notice::read(event) }?;
        let group = Arc::new(Self { remaining: AtomicU32::new(1),
            signal: if matches!(notice, Notice::Thread { .. }) { Notice::None } else { notice } });
        if matches!(notice, Notice::Thread { .. }) {
            struct Waiter { group: Arc<Group>, notice: Notice }
            unsafe extern "C-unwind" fn entry(arg: *mut c_void) -> *mut c_void {
                detach_current();
                // SAFETY: spawn transferred this allocation to exactly one worker.
                let Waiter { group, notice } = *unsafe { Box::from_raw(arg.cast::<Waiter>()) };
                loop {
                    let remaining = group.remaining.load(Ordering::Acquire);
                    if remaining == 0 { break; }
                    // No public cancellation point or locks in this internal
                    // waiter. EINTR and racing completions simply recheck.
                    let _ = unsafe { raw::sys_futex(
                        &group.remaining as *const AtomicU32 as *const u32,
                        libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                        remaining, 0, 0, 0) };
                }
                drop(group);
                unsafe { notice.deliver() };
                std::ptr::null_mut()
            }
            let waiter = Box::into_raw(Box::new(Waiter { group: Arc::clone(&group), notice }));
            if let Err(error) = unsafe { spawn(entry, waiter.cast(), attributes) } {
                // SAFETY: creation failed, so no worker owns the allocation.
                drop(unsafe { Box::from_raw(waiter) });
                return Err(error);
            }
        }
        Ok(group)
    }

    pub(super) fn reserve(&self) {
        // nent is a nonnegative c_int, so outstanding requests plus the
        // submission reservation fit in u32.
        self.remaining.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn finish(&self) {
        if self.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
            wake(&self.remaining);
            // SAFETY: thread callbacks are handled by a separate waiter; this
            // final completion may only queue a signal, not run user code.
            unsafe { self.signal.deliver() };
        }
    }
}
