//! Owned GNU asynchronous resolver requests, backed by the native resolver.
//!
//! Queue membership linearizes starting, cancellation and result publication.
//! No worker reads caller-owned request storage after publishing its status.
//! Waiters retain request identities, not reusable gaicb addresses. A batch owns
//! counters rather than its caller's list; notification may reap/free the whole
//! list, resubmit requests, or leave through pthread_exit.

use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use super::{aio_completion, read_c_string_bytes, set_abi_errno, tracked_region_fits};
use frankenlibc_core::syscall as raw;

// DNS and file I/O have independent wait domains. A burst of lookups must not
// awaken every aio_suspend caller or reusable file-I/O worker in the process.
pub(super) static EPOCH: AtomicU32 = AtomicU32::new(0);

fn publish() {
    EPOCH.fetch_add(1, Ordering::Release);
    aio_completion::wake(&EPOCH);
}

pub(super) fn wait(expected: u32, timeout: *const libc::timespec) -> Result<(), c_int> {
    // SAFETY: the word has static lifetime and callers supply null or a live
    // timespec. Cancellation belongs to the public ABI frame, not this helper.
    unsafe {
        raw::sys_futex(
            &EPOCH as *const AtomicU32 as *const u32,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected, timeout as usize, 0, 0,
        )
    }.map(|_| ())
}

pub(super) const INPROGRESS: c_int = -100;
pub(super) const CANCELED: c_int = -101;
pub(super) const NOTCANCELED: c_int = -102;
pub(super) const ALLDONE: c_int = -103;
pub(super) const INTR: c_int = -104;
const SI_ASYNCNL: c_int = -60;
const WORKER_LIMIT: usize = 20;
const IDLE_TIME: Duration = Duration::from_secs(1);

/// Linux LP64 gaicb, including its status field. The external C fixture checks
/// sizeof and both output offsets against <netdb.h>, not a Rust-only mirror.
#[repr(C)]
struct Gaicb {
    name: *const c_char,
    service: *const c_char,
    hints: *const libc::addrinfo,
    result: *mut libc::addrinfo,
    error: c_int,
    unused: [c_int; 5],
}

const _: () = {
    assert!(std::mem::size_of::<Gaicb>() == 56);
    assert!(std::mem::offset_of!(Gaicb, result) == 24);
    assert!(std::mem::offset_of!(Gaicb, error) == 32);
};

#[derive(Clone, Copy)]
struct Hints {
    flags: c_int,
    family: c_int,
    socktype: c_int,
    protocol: c_int,
}

struct Input {
    name: Option<CString>,
    service: Option<CString>,
    hints: Option<Hints>,
}

fn bad_pointer() -> c_int {
    // Keep the established safe divergence for null/short tracked inputs.
    unsafe { set_abi_errno(libc::ENOSYS) };
    libc::EAI_SYSTEM
}

fn valid_request(cb: *const c_void) -> bool {
    !cb.is_null()
        && (cb as usize).is_multiple_of(std::mem::align_of::<Gaicb>())
        && tracked_region_fits(cb as usize, std::mem::size_of::<Gaicb>())
}

unsafe fn copy_name(name: *const c_char) -> Result<Option<CString>, c_int> {
    if name.is_null() {
        return Ok(None);
    }
    // SAFETY: the shared ABI helper validates tracked extents while scanning.
    let bytes = unsafe { read_c_string_bytes(name) }.ok_or_else(bad_pointer)?;
    CString::new(bytes).map(Some).map_err(|_| bad_pointer())
}

impl Input {
    unsafe fn read(cb: *const c_void) -> Result<Self, c_int> {
        if !valid_request(cb) {
            return Err(bad_pointer());
        }
        let cb = cb.cast::<Gaicb>();
        // Read the three input fields individually: ar_result and the private
        // status/reserved fields need not have been initialized by a C caller.
        let name = unsafe { std::ptr::addr_of!((*cb).name).read() };
        let service = unsafe { std::ptr::addr_of!((*cb).service).read() };
        let hints = unsafe { std::ptr::addr_of!((*cb).hints).read() };
        let hints = if hints.is_null() {
            None
        } else {
            if !(hints as usize).is_multiple_of(std::mem::align_of::<libc::addrinfo>())
                || !tracked_region_fits(hints as usize, std::mem::size_of::<libc::addrinfo>())
            {
                return Err(bad_pointer());
            }
            // Only the input integers are relevant. Never retain any pointer
            // from the caller's hints or read its unused pointer fields.
            Some(Hints {
                flags: unsafe { std::ptr::addr_of!((*hints).ai_flags).read() },
                family: unsafe { std::ptr::addr_of!((*hints).ai_family).read() },
                socktype: unsafe { std::ptr::addr_of!((*hints).ai_socktype).read() },
                protocol: unsafe { std::ptr::addr_of!((*hints).ai_protocol).read() },
            })
        };
        Ok(Self {
            name: unsafe { copy_name(name) }?,
            service: unsafe { copy_name(service) }?,
            hints,
        })
    }

    fn resolve(&self) -> (*mut libc::addrinfo, c_int) {
        let hints = self.hints.map(|h| libc::addrinfo {
            ai_flags: h.flags,
            ai_family: h.family,
            ai_socktype: h.socktype,
            ai_protocol: h.protocol,
            ai_addrlen: 0,
            ai_addr: std::ptr::null_mut(),
            ai_canonname: std::ptr::null_mut(),
            ai_next: std::ptr::null_mut(),
        });
        let mut result = std::ptr::null_mut();
        // SAFETY: all input storage is owned by this request, and result is a
        // live local output slot. Keep the native resolver/freeaddrinfo pair;
        // do not introduce a host getaddrinfo_a ownership domain.
        let error = unsafe {
            crate::resolv_abi::getaddrinfo(
                self.name.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                self.service.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                hints.as_ref().map_or(std::ptr::null(), |h| h as *const _),
                &mut result,
            )
        };
        (result, error)
    }
}

/// Publish even a failed admission without leaving an unserviceable request
/// apparently in progress. Call only for validated, exclusively owned gaicbs.
unsafe fn publish_status(address: usize, result: *mut libc::addrinfo, error: c_int) {
    let cb = address as *mut Gaicb;
    // SAFETY: all users validate the complete object before taking ownership.
    unsafe {
        std::ptr::addr_of_mut!((*cb).result).write(result);
        (&*std::ptr::addr_of!((*cb).error).cast::<AtomicI32>())
            .store(error, Ordering::Release);
    }
}

struct Request {
    cb: usize,
    input: Input,
    error: AtomicI32,
    group: Arc<aio_completion::Group>,
}

impl Request {
    /// Requires QUEUE and exclusive completion ownership. The release store
    /// to gaicb.error is the LAST access to any caller-owned request storage.
    unsafe fn publish(&self, result: *mut libc::addrinfo, error: c_int) {
        // SAFETY: the caller holds exclusive publication ownership.
        unsafe { publish_status(self.cb, result, error) };
        self.error.store(error, Ordering::Release);
    }

    fn notify(&self) {
        // No queue/submission lock can be held at final batch notification.
        self.group.finish();
        // Publish AFTER the batch decrement, so GAI_WAIT cannot miss the last
        // transition by seeing a new epoch alongside an old remaining count.
        publish();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Queued,
    Running,
    Canceled,
}

struct Pending {
    request: Arc<Request>,
    state: State,
}

struct Queue {
    pending: Vec<Pending>,
    // Includes reserved, not-yet-started workers.
    workers: usize,
}

static QUEUE: Mutex<Queue> = Mutex::new(Queue { pending: Vec::new(), workers: 0 });
// Serialize admission transactions, not execution. A failed first spawn must
// never leave another submitter's accepted requests with no worker.
static SUBMISSIONS: Mutex<()> = Mutex::new(());

fn queue() -> MutexGuard<'static, Queue> {
    QUEUE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

unsafe extern "C-unwind" fn worker(_arg: *mut c_void) -> *mut c_void {
    aio_completion::detach_current();
    let mut idle_since = None;
    loop {
        let epoch = EPOCH.load(Ordering::Acquire);
        let (request, remaining) = {
            let mut q = queue();
            if let Some(index) = q.pending.iter().position(|p| p.state == State::Queued) {
                q.pending[index].state = State::Running;
                idle_since = None;
                (Some(Arc::clone(&q.pending[index].request)), Duration::ZERO)
            } else {
                let elapsed = idle_since.get_or_insert_with(Instant::now).elapsed();
                if elapsed >= IDLE_TIME {
                    q.workers -= 1;
                    break;
                }
                (None, IDLE_TIME - elapsed)
            }
        };
        if let Some(request) = request {
            let (result, error) = request.input.resolve();
            {
                let mut q = queue();
                let index = q.pending.iter().position(|p| Arc::ptr_eq(&p.request, &request))
                    .expect("running resolver request retains completion ownership");
                // SAFETY: cancellation never removes an executing resolver.
                unsafe { request.publish(result, error) };
                q.pending.remove(index);
            }
            request.notify();
        } else {
            let timeout = libc::timespec {
                tv_sec: remaining.as_secs() as libc::time_t,
                tv_nsec: remaining.subsec_nanos() as libc::c_long,
            };
            // Internal worker wait, never an application cancellation point.
            let _ = wait(epoch, &timeout);
        }
    }
    std::ptr::null_mut()
}

pub(super) struct Submission {
    pub(super) status: c_int,
    group: Option<Arc<aio_completion::Group>>,
}

impl Submission {
    pub(super) fn done(&self) -> bool {
        self.group.as_ref().is_none_or(|group| group.is_complete())
    }
}

pub(super) unsafe fn submit(
    mode: c_int,
    list: *mut *mut c_void,
    nitems: c_int,
    event: *mut c_void,
) -> Result<Submission, c_int> {
    if mode != 0 && mode != 1 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return Err(libc::EAI_SYSTEM);
    }
    // Preserve GNU's existing empty/negative-count no-op, without inspecting
    // an event that cannot describe a real request.
    if nitems <= 0 {
        return Ok(Submission { status: 0, group: None });
    }
    let count = nitems as usize;
    let list_bytes = count.checked_mul(std::mem::size_of::<*mut c_void>())
        .ok_or_else(bad_pointer)?;
    if list.is_null() || !(list as usize).is_multiple_of(std::mem::align_of::<*mut c_void>())
        || !tracked_region_fits(list as usize, list_bytes)
    {
        return Err(bad_pointer());
    }
    let mut inputs = Vec::new();
    inputs.try_reserve(count).map_err(|_| libc::EAI_MEMORY)?;
    // Snapshot the COMPLETE list before a fast worker can finish or a callback
    // can release it. Zeroed descriptors are real getaddrinfo(NULL,NULL) jobs,
    // not successful lookups: their final error must be EAI_NONAME.
    for index in 0..count {
        let cb = unsafe { list.add(index).read() };
        if cb.is_null() {
            continue;
        }
        if inputs.iter().any(|(address, _)| *address == cb as usize) {
            unsafe { set_abi_errno(libc::EINVAL) };
            return Err(libc::EAI_SYSTEM);
        }
        inputs.push((cb as usize, unsafe { Input::read(cb) }?));
    }
    let submission = SUBMISSIONS.lock().unwrap_or_else(|p| p.into_inner());
    {
        let mut q = queue();
        if inputs.iter().any(|(cb, _)| q.pending.iter().any(|p| {
            p.state != State::Canceled && p.request.cb == *cb
        })) {
            // Undefined overlapping use: leave the live request untouched.
            unsafe { set_abi_errno(libc::EINVAL) };
            return Err(libc::EAI_SYSTEM);
        }
        q.pending.try_reserve(inputs.len()).map_err(|_| libc::EAI_MEMORY)?;
    }
    // GAI_WAIT must not even inspect event. The Group consumes thread
    // attributes now and holds one reservation until all entries are admitted.
    let event = if mode == 1 { event } else { std::ptr::null_mut() };
    if !event.is_null()
        && (!(event as usize).is_multiple_of(std::mem::align_of::<libc::sigevent>())
            || !tracked_region_fits(event as usize, std::mem::size_of::<libc::sigevent>()))
    {
        return Err(bad_pointer());
    }
    let group = match unsafe { aio_completion::Group::new_with_code(event.cast(), SI_ASYNCNL) } {
        Ok(group) => group,
        Err(error) => {
            if error == libc::EINVAL {
                unsafe { set_abi_errno(error) };
                return Err(libc::EAI_SYSTEM);
            }
            // No batch was admitted and no worker can own these outputs.
            // Distinguish exhausted notification resources from a lookup that
            // was accepted: every member has a terminal retryable status.
            for (cb, _) in &inputs {
                unsafe { publish_status(*cb, std::ptr::null_mut(), libc::EAI_AGAIN) };
            }
            return Err(libc::EAI_AGAIN);
        }
    };
    let mut status = 0;
    for (cb, input) in inputs {
        let request = Arc::new(Request {
            cb, input, error: AtomicI32::new(INPROGRESS), group: Arc::clone(&group),
        });
        let spawn = {
            let mut q = queue();
            group.reserve();
            unsafe { request.publish(std::ptr::null_mut(), INPROGRESS) };
            q.pending.push(Pending { request: Arc::clone(&request), state: State::Queued });
            let spawn = q.workers < WORKER_LIMIT
                && q.pending.iter().filter(|p| p.state != State::Canceled).count() > q.workers;
            if spawn { q.workers += 1; }
            spawn
        };
        publish();
        if spawn && unsafe {
            aio_completion::spawn(worker, std::ptr::null_mut(), std::ptr::null())
        }.is_err() {
            let failed = {
                let mut q = queue();
                q.workers -= 1;
                if q.workers == 0 {
                    if let Some(index) = q.pending.iter().position(|p| {
                        p.state == State::Queued && Arc::ptr_eq(&p.request, &request)
                    }) {
                        unsafe { request.publish(std::ptr::null_mut(), libc::EAI_AGAIN) };
                        q.pending.remove(index);
                        true
                    } else { false } // cancellation already completed it
                } else { false } // an existing worker owns eventual progress
            };
            if failed {
                // The submission reservation prevents a final notification
                // here, even though SUBMISSIONS still protects admission.
                request.notify();
                status = libc::EAI_AGAIN;
            }
        }
    }
    drop(submission);
    // This can notify immediately. Never inspect caller storage after it.
    group.finish();
    publish();
    Ok(Submission { status, group: Some(group) })
}

pub(super) unsafe fn error(cb: *mut c_void) -> Result<c_int, c_int> {
    if !valid_request(cb) {
        return Err(bad_pointer());
    }
    // SAFETY: status is naturally aligned in a validated gaicb. Acquire pairs
    // with the producer's final release, including publication of ar_result.
    Ok(unsafe { (&*std::ptr::addr_of!((*(cb.cast::<Gaicb>())).error).cast::<AtomicI32>())
        .load(Ordering::Acquire) })
}

pub(super) fn cancel(cb: *mut c_void) -> c_int {
    let mut canceled = 0;
    let mut running = false;
    {
        let mut q = queue();
        for entry in &mut q.pending {
            if entry.state == State::Canceled || (!cb.is_null() && entry.request.cb != cb as usize) {
                continue;
            }
            if entry.state == State::Running {
                running = true;
            } else {
                // SAFETY: QUEUE excludes starting this resolver. Its worker
                // cannot subsequently access the caller's request or inputs.
                unsafe { entry.request.publish(std::ptr::null_mut(), CANCELED) };
                entry.state = State::Canceled;
                canceled += 1;
            }
        }
    }
    if canceled != 0 {
        publish();
    }
    // Reuse canceled slots as the notification worklist: no allocation and no
    // callback under QUEUE. Concurrent cancelers may help drain one another.
    for _ in 0..canceled {
        let request = {
            let mut q = queue();
            let Some(index) = q.pending.iter().position(|p| p.state == State::Canceled) else { break; };
            q.pending.remove(index).request
        };
        request.notify();
    }
    if running { NOTCANCELED } else if canceled != 0 { CANCELED } else { ALLDONE }
}

pub(super) struct WaitSet(Vec<Arc<Request>>);

impl WaitSet {
    pub(super) unsafe fn read(list: *const *const c_void, count: c_int) -> Result<Self, c_int> {
        if count <= 0 || list.is_null() {
            return Ok(Self(Vec::new()));
        }
        let count = count as usize;
        let bytes = count.checked_mul(std::mem::size_of::<*const c_void>()).ok_or_else(bad_pointer)?;
        if !(list as usize).is_multiple_of(std::mem::align_of::<*const c_void>())
            || !tracked_region_fits(list as usize, bytes)
        {
            return Err(bad_pointer());
        }
        let mut waiting = Vec::new();
        waiting.try_reserve(count).map_err(|_| libc::EAI_MEMORY)?;
        let q = queue();
        for index in 0..count {
            let cb = unsafe { list.add(index).read() };
            if cb.is_null() { continue; }
            if let Some(entry) = q.pending.iter().find(|p| {
                p.state != State::Canceled && p.request.cb == cb as usize
            }) {
                waiting.push(Arc::clone(&entry.request));
            }
        }
        Ok(Self(waiting))
    }

    pub(super) fn is_empty(&self) -> bool { self.0.is_empty() }

    pub(super) fn completed(&self) -> bool {
        self.0.iter().any(|request| request.error.load(Ordering::Acquire) != INPROGRESS)
    }
}
