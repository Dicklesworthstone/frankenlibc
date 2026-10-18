//! Bounded POSIX AIO workers with per-descriptor ordering.
//!
//! Queued requests own snapshots, not threads. The queue lock linearizes
//! starting, cancellation and final status publication. Callback waiters have
//! separate lifetimes: user callbacks never occupy an I/O worker, even when
//! they submit and wait for another request or leave via pthread_exit.

use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use super::{
    AioOp, aio_completion, aio_execute, aiocb_i32, aiocb_i64, aiocb_off, aiocb_ptr,
    aiocb_set_error_atomic, aiocb_set_return, aiocb_usize, current_abi_errno, set_abi_errno,
};
use frankenlibc_core::syscall as raw;

const WAITING: u32 = 0;
const NOTIFY: u32 = 1;
const ABANDON: u32 = 2;
const COMPLETING: u32 = 3;

struct Request {
    cb: usize,
    fd: c_int,
    buffer: usize,
    length: usize,
    offset: i64,
    op: AioOp,
    notice: aio_completion::Notice,
    group: Option<Arc<aio_completion::Group>>,
    completion: AtomicU32,
}

impl Request {
    // Only accepted requests own a group reservation. No queue/submission
    // lock may be held here: a signal handler or callback can run immediately.
    fn complete(&self, notify: bool) {
        if self
            .completion
            .compare_exchange(WAITING, COMPLETING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        if let Some(group) = &self.group {
            group.finish();
        }
        self.completion
            .store(if notify { NOTIFY } else { ABANDON }, Ordering::Release);
        if matches!(self.notice, aio_completion::Notice::Thread { .. }) {
            aio_completion::wake(&self.completion);
        } else if notify {
            // SAFETY: this is only a signal or no-op, never a user callback.
            unsafe { self.notice.deliver() };
        }
    }

    // Submission failed before reserving a batch member. Retire a precreated
    // callback waiter without delivering an event for an unaccepted request.
    fn abandon(&self) {
        self.completion.store(ABANDON, Ordering::Release);
        aio_completion::wake(&self.completion);
    }
}

#[path = "aio_scheduler.rs"]
mod scheduler;
use scheduler::{Pending, Queue, State};

// No blocking I/O, callbacks, pthread creation or cancellation points while
// QUEUE is held. SUBMISSIONS serializes creation transactions, not execution;
// this prevents accepting orphaned work behind a first-worker spawn failure.
static QUEUE: Mutex<Queue<Arc<Request>>> = Mutex::new(Queue::new());
static SUBMISSIONS: Mutex<()> = Mutex::new(());

fn queue() -> MutexGuard<'static, Queue<Arc<Request>>> {
    QUEUE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// GNU struct aioinit is eight consecutive C ints on the supported ABIs.
/// The hint is consumed only here; it is never retained by a worker.
pub(super) unsafe fn init(hint: *const c_void) {
    if hint.is_null() {
        return;
    }
    let _submission = SUBMISSIONS.lock().unwrap_or_else(|p| p.into_inner());
    let mut q = queue();
    if !q.started {
        // SAFETY: aio_init's caller supplies a live platform struct aioinit.
        let fields = hint.cast::<c_int>();
        // Read only the three meaningful fields; unused ints need not have
        // been initialized by C callers.
        q.limit = unsafe { fields.read() }.max(1) as usize;
        q.expected = unsafe { fields.add(1).read() }.max(32) as usize;
        q.idle = Duration::from_secs(unsafe { fields.add(6).read() }.max(0) as u64);
    }
}

/// LAST access to caller storage. Hold QUEUE so ALLDONE cannot precede status.
unsafe fn status(cb: usize, result: isize, error: c_int) {
    // SAFETY: this accepted queue entry exclusively owns final publication.
    unsafe {
        aiocb_set_return(cb as *mut c_void, result);
        aiocb_set_error_atomic(cb as *mut c_void, error);
    }
}

// Retain canceled snapshots in the existing vector until this out-of-lock
// drain, avoiding an allocation in aio_cancel and notifying even if every I/O
// worker is blocked. The bounded count prevents chasing concurrent producers.
fn drain_canceled(count: usize) {
    for _ in 0..count {
        let request = {
            let mut q = queue();
            let Some(index) = q.pending.iter().position(|p| p.state == State::Canceled) else {
                break;
            };
            q.pending.remove(index).request
        };
        request.complete(true);
    }
}

unsafe extern "C-unwind" fn callback_waiter(arg: *mut c_void) -> *mut c_void {
    aio_completion::detach_current();
    // SAFETY: successful spawn transfers this allocation exactly once.
    let request = *unsafe { Box::from_raw(arg.cast::<Arc<Request>>()) };
    let ready = loop {
        let ready = request.completion.load(Ordering::Acquire);
        if ready == NOTIFY || ready == ABANDON {
            break ready;
        }
        // SAFETY: this Arc retains the aligned futex word through the wait.
        let _ = unsafe {
            raw::sys_futex(
                &request.completion as *const AtomicU32 as *const u32,
                libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                ready,
                0,
                0,
                0,
            )
        };
    };
    let notice = request.notice;
    drop(request);
    if ready == NOTIFY {
        // SAFETY: detached notification thread, no queue or request ownership.
        unsafe { notice.deliver() };
    }
    std::ptr::null_mut()
}

unsafe extern "C-unwind" fn worker(_arg: *mut c_void) -> *mut c_void {
    aio_completion::detach_current();
    let mut idle_since = None;
    loop {
        // Observe before scanning to avoid lost wakes from submission/finish.
        let epoch = aio_completion::EPOCH.load(Ordering::Acquire);
        let (request, remaining) = {
            let mut q = queue();
            if let Some(index) = q.runnable() {
                q.pending[index].state = State::Running;
                idle_since = None;
                (Some(Arc::clone(&q.pending[index].request)), Duration::ZERO)
            } else {
                let elapsed = idle_since.get_or_insert_with(Instant::now).elapsed();
                if elapsed >= q.idle {
                    // Retirement and admission share this lock. A new request
                    // either wakes a counted worker or reserves its replacement.
                    q.workers -= 1;
                    break;
                }
                (None, q.idle - elapsed)
            }
        };
        if let Some(request) = request {
            let result = aio_execute(
                request.fd,
                request.buffer,
                request.length,
                request.offset,
                request.op,
            );
            let error = if result < 0 { current_abi_errno() } else { 0 };
            {
                let mut q = queue();
                let index = q
                    .pending
                    .iter()
                    .position(|p| Arc::ptr_eq(&p.request, &request))
                    .expect("running AIO retains queue ownership");
                // SAFETY: running requests cannot be removed by aio_cancel.
                unsafe { status(request.cb, result as isize, error) };
                q.pending.remove(index);
            }
            aio_completion::publish();
            request.complete(true);
        } else {
            let timeout = libc::timespec {
                tv_sec: remaining.as_secs() as libc::time_t,
                tv_nsec: remaining.subsec_nanos() as libc::c_long,
            };
            let _ = aio_completion::wait(epoch, &timeout);
        }
    }
    std::ptr::null_mut()
}

pub(super) unsafe fn submit(
    cb: *mut c_void,
    op: AioOp,
    group: Option<Arc<aio_completion::Group>>,
) -> c_int {
    // SAFETY: the exported entrypoint checked cb; submission borrows its event.
    let (notice, attributes) = match unsafe {
        aio_completion::Notice::read((cb as *const u8).add(32).cast::<libc::sigevent>())
    } {
        Ok(value) => value,
        Err(error) => {
            unsafe {
                status(cb as usize, -1, error);
                set_abi_errno(error);
            }
            return -1;
        }
    };
    let request = Arc::new(Request {
        cb: cb as usize,
        // SAFETY: the caller keeps this control block live during submission.
        fd: unsafe { aiocb_i32(cb, aiocb_off::FILDES) },
        buffer: unsafe { aiocb_ptr(cb, aiocb_off::BUF) } as usize,
        length: unsafe { aiocb_usize(cb, aiocb_off::NBYTES) },
        offset: unsafe { aiocb_i64(cb, aiocb_off::OFFSET) },
        op,
        notice,
        group,
        completion: AtomicU32::new(WAITING),
    });
    let submission = SUBMISSIONS.lock().unwrap_or_else(|p| p.into_inner());
    {
        let mut q = queue();
        if q.pending
            .iter()
            .any(|p| p.state != State::Canceled && p.request.cb == request.cb)
        {
            // Undefined overlapping submission: do not corrupt the live result.
            unsafe { set_abi_errno(libc::EINVAL) };
            return -1;
        }
        if !q.started {
            // aio_num is an allocation hint, NOT an admission limit. A failed
            // speculative reservation must not reject an otherwise small request.
            let expected = q.expected;
            let _ = q.pending.try_reserve(expected);
        }
        if q.pending.try_reserve(1).is_err() {
            unsafe {
                status(request.cb, -1, libc::EAGAIN);
                set_abi_errno(libc::EAGAIN);
            }
            return -1;
        }
    }
    if matches!(notice, aio_completion::Notice::Thread { .. }) {
        let argument = Box::into_raw(Box::new(Arc::clone(&request)));
        // SAFETY: attributes are consumed now, never borrowed until completion.
        if unsafe { aio_completion::spawn(callback_waiter, argument.cast(), attributes) }.is_err() {
            // SAFETY: failed creation did not transfer this allocation.
            drop(unsafe { Box::from_raw(argument) });
            request.abandon();
            unsafe {
                status(request.cb, -1, libc::EAGAIN);
                set_abi_errno(libc::EAGAIN);
            }
            return -1;
        }
    }
    let spawn = {
        let mut q = queue();
        if let Some(group) = &request.group {
            group.reserve();
        }
        unsafe { status(request.cb, 0, libc::EINPROGRESS) };
        q.pending.push(Pending {
            request: Arc::clone(&request),
            fd: request.fd,
            state: State::Queued,
        });
        q.started = true;
        let spawn = q.needs_worker();
        if spawn {
            q.workers += 1;
        }
        spawn
    };
    // Wake an existing idle worker; blocked same-fd requests need no new thread.
    aio_completion::publish();
    if spawn {
        // SAFETY: the pool worker takes no caller argument or callback attributes.
        if unsafe { aio_completion::spawn(worker, std::ptr::null_mut(), std::ptr::null()) }.is_err()
        {
            let failed =
                {
                    let mut q = queue();
                    q.workers -= 1;
                    if q.workers == 0 {
                        if let Some(index) = q.pending.iter().position(|p| {
                            p.state == State::Queued && Arc::ptr_eq(&p.request, &request)
                        }) {
                            unsafe { status(request.cb, -1, libc::EAGAIN) };
                            q.pending.remove(index);
                            true
                        } else {
                            false
                        } // cancellation already completed admission
                    } else {
                        false
                    } // an existing worker owns eventual progress
                };
            drop(submission);
            if failed {
                aio_completion::publish();
                request.complete(false);
                unsafe { set_abi_errno(libc::EAGAIN) };
                return -1;
            }
            return 0;
        }
    }
    0
}

pub(super) unsafe fn cancel(fd: c_int, cb: *mut c_void) -> c_int {
    // SAFETY: F_GETFL validates the descriptor without accessing caller storage.
    if let Err(error) = unsafe { raw::sys_fcntl(fd, libc::F_GETFL, 0) } {
        unsafe { set_abi_errno(error) };
        return -1;
    }
    let mut canceled = 0;
    let mut running = false;
    {
        let mut q = queue();
        if !cb.is_null()
            && q.pending.iter().any(|p| {
                p.state != State::Canceled && p.request.cb == cb as usize && p.request.fd != fd
            })
        {
            unsafe { set_abi_errno(libc::EINVAL) };
            return -1;
        }
        for entry in &mut q.pending {
            if entry.state == State::Canceled
                || entry.request.fd != fd
                || (!cb.is_null() && entry.request.cb != cb as usize)
            {
                continue;
            }
            if entry.state == State::Running {
                running = true;
            } else {
                // SAFETY: QUEUE excludes starting this syscall. Canceled slots
                // are ignored by admission/scheduling and never touch cb again.
                unsafe { status(entry.request.cb, -1, libc::ECANCELED) };
                entry.state = State::Canceled;
                canceled += 1;
            }
        }
    }
    if canceled != 0 {
        aio_completion::publish();
        drain_canceled(canceled);
    }
    if running {
        super::AIO_NOTCANCELED
    } else if canceled != 0 {
        super::AIO_CANCELED
    } else {
        super::AIO_ALLDONE
    }
}
