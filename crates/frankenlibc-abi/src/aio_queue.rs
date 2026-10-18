//! Per-descriptor AIO scheduling and cancellation ownership.
//!
//! The queue lock is the linearization point for starting, canceling, and
//! completing a request. Only the first request for a descriptor may issue I/O;
//! consequently an fsync cannot overtake writes already submitted on that fd.
//! Cancellation removes queued requests and publishes ECANCELED synchronously.
//! Their already-created workers deliver notifications without ever touching
//! the caller's aiocb or buffer again. Arc identity (not a reusable cb address)
//! distinguishes an old notification worker from a new submission.

use std::ffi::{c_int, c_void};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

use super::{
    AioOp, aio_completion, aio_execute, aiocb_i32, aiocb_i64, aiocb_off, aiocb_ptr,
    aiocb_set_error_atomic, aiocb_set_return, aiocb_usize, current_abi_errno, set_abi_errno,
};
use frankenlibc_core::syscall as raw;

struct Request {
    cb: usize,
    fd: c_int,
    buffer: usize,
    length: usize,
    offset: i64,
    op: AioOp,
    notice: aio_completion::Notice,
    group: Option<Arc<aio_completion::Group>>,
}

struct Pending {
    request: Arc<Request>,
    running: bool,
}

// No callbacks, blocking I/O, pthread creation, or cancellation points are
// entered while this lock is held. Rust's Linux mutex uses a private futex.
static QUEUE: Mutex<Vec<Pending>> = Mutex::new(Vec::new());

fn queue() -> MutexGuard<'static, Vec<Pending>> {
    QUEUE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Publish the result as the LAST access to caller-owned storage. Must hold
/// the queue lock so cancel cannot report ALLDONE before the status is visible.
unsafe fn status(cb: usize, result: isize, error: c_int) {
    unsafe {
        aiocb_set_return(cb as *mut c_void, result);
        aiocb_set_error_atomic(cb as *mut c_void, error);
    }
}

fn start(request: &Arc<Request>) -> bool {
    loop {
        // Observe before scanning: completion/cancellation between the scan
        // and futex entry changes the epoch and makes the wait return EAGAIN.
        let epoch = aio_completion::EPOCH.load(Ordering::Acquire);
        {
            let mut pending = queue();
            let Some(index) = pending
                .iter()
                .position(|p| Arc::ptr_eq(&p.request, request))
            else {
                return false; // cancellation already published and removed it
            };
            if !pending[..index].iter().any(|p| p.request.fd == request.fd) {
                pending[index].running = true;
                return true;
            }
        }
        // Internal wait: never cancel a worker holding completion ownership.
        let _ = aio_completion::wait(epoch, std::ptr::null());
    }
}

fn finish(request: &Arc<Request>, result: isize, error: c_int) {
    {
        let mut pending = queue();
        if let Some(index) = pending
            .iter()
            .position(|p| Arc::ptr_eq(&p.request, request))
        {
            // SAFETY: this entry still owns completion, excluding aio_cancel.
            unsafe { status(request.cb, result, error) };
            pending.remove(index);
        }
        // If absent, aio_cancel already published ECANCELED. Never overwrite
        // it: the application may already have freed or reused this address.
    }
    aio_completion::publish();
}

unsafe extern "C-unwind" fn worker(arg: *mut c_void) -> *mut c_void {
    aio_completion::detach_current();
    // SAFETY: successful pthread creation transfers this allocation once.
    let request = *unsafe { Box::from_raw(arg.cast::<Arc<Request>>()) };
    if start(&request) {
        let result = aio_execute(
            request.fd,
            request.buffer,
            request.length,
            request.offset,
            request.op,
        );
        // Capture syscall errno before any synchronization/allocator operation.
        let error = if result < 0 { current_abi_errno() } else { 0 };
        finish(&request, result as isize, error);
    }
    let notice = request.notice;
    let group = request.group.clone();
    drop(request);
    if let Some(group) = group {
        group.finish();
    }
    // No queue ownership or caller-storage access remains. The callback may
    // submit another request on this fd, free the old one, or pthread_exit.
    unsafe { notice.deliver() };
    std::ptr::null_mut()
}

pub(super) unsafe fn submit(
    cb: *mut c_void,
    op: AioOp,
    group: Option<Arc<aio_completion::Group>>,
) -> c_int {
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
        fd: unsafe { aiocb_i32(cb, aiocb_off::FILDES) },
        buffer: unsafe { aiocb_ptr(cb, aiocb_off::BUF) } as usize,
        length: unsafe { aiocb_usize(cb, aiocb_off::NBYTES) },
        offset: unsafe { aiocb_i64(cb, aiocb_off::OFFSET) },
        op,
        notice,
        group,
    });
    {
        let mut pending = queue();
        // Simultaneous use of one aiocb is outside POSIX's contract; fail
        // without corrupting the result of the live operation.
        if pending.iter().any(|p| p.request.cb == request.cb) {
            unsafe { set_abi_errno(libc::EINVAL) };
            return -1;
        }
        if pending.try_reserve(1).is_err() {
            unsafe {
                status(request.cb, -1, libc::EAGAIN);
                set_abi_errno(libc::EAGAIN);
            }
            return -1;
        }
        if let Some(group) = &request.group {
            group.reserve();
        }
        unsafe { status(request.cb, 0, libc::EINPROGRESS) };
        pending.push(Pending {
            request: Arc::clone(&request),
            running: false,
        });
    }
    let argument = Box::into_raw(Box::new(Arc::clone(&request)));
    // Consume attributes during submission, even for queued notifications.
    match unsafe { aio_completion::spawn(worker, argument.cast(), attributes) } {
        Ok(()) => 0,
        Err(_) => {
            // SAFETY: failed creation leaves allocation ownership here.
            drop(unsafe { Box::from_raw(argument) });
            finish(&request, -1, libc::EAGAIN);
            if let Some(group) = &request.group {
                group.finish();
            }
            unsafe { set_abi_errno(libc::EAGAIN) };
            -1
        }
    }
}

pub(super) unsafe fn cancel(fd: c_int, cb: *mut c_void) -> c_int {
    // POSIX requires EBADF even when the request set happens to be empty.
    if let Err(error) = unsafe { raw::sys_fcntl(fd, libc::F_GETFL, 0) } {
        unsafe { set_abi_errno(error) };
        return -1;
    }
    let mut canceled = false;
    let mut running = false;
    {
        let mut pending = queue();
        if !cb.is_null()
            && pending
                .iter()
                .any(|p| p.request.cb == cb as usize && p.request.fd != fd)
        {
            unsafe { set_abi_errno(libc::EINVAL) };
            return -1;
        }
        pending.retain(|entry| {
            if entry.request.fd != fd || (!cb.is_null() && entry.request.cb != cb as usize) {
                return true;
            }
            if entry.running {
                running = true;
                return true; // an executing syscall still owns the buffer
            }
            // SAFETY: no worker can start until this lock is released, and
            // removing the entry tells its worker to skip every buffer access.
            unsafe { status(entry.request.cb, -1, libc::ECANCELED) };
            canceled = true;
            false
        });
    }
    if canceled {
        aio_completion::publish();
    }
    if running {
        super::AIO_NOTCANCELED
    } else if canceled {
        super::AIO_CANCELED
    } else {
        super::AIO_ALLDONE
    }
}
