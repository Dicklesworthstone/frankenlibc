//! POSIX message-queue SIGEV_THREAD delivery through Linux's netlink cookie
//! protocol. One receiver owns one socket per process. Each registration owns
//! its callback and attributes until the kernel reports delivery or removal.

use std::ffi::{c_int, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use frankenlibc_core::syscall as raw;

use super::aio_completion::{self, Notice};
use crate::pthread_abi::NotificationThreadAttributes;
use crate::util::{ArtifactHashMap, artifact_hash_map};

// Linux UAPI, include/uapi/linux/mqueue.h. The kernel copies all 32 bytes and
// changes only the final byte when it sends the registration's notification.
const COOKIE_LEN: usize = 32;
const WOKEN_UP: u8 = 1;
const REMOVED: u8 = 2;
const MAGIC: &[u8; 8] = b"FLMQ0001";
const HELPER_STACK_SIZE: usize = 256 * 1024;

struct Registration {
    notice: Notice,
    attributes: Option<NotificationThreadAttributes>,
}

struct QueueRuntime {
    pid: c_int,
    socket: AtomicI32,
    socket_cookie: AtomicU64,
    helper_tid: AtomicI32,
    helper_start: Mutex<()>,
    registrations: Mutex<ArtifactHashMap<usize, Registration>>,
}

static RUNTIME: AtomicPtr<QueueRuntime> = AtomicPtr::new(std::ptr::null_mut());
static NEXT_TOKEN: AtomicUsize = AtomicUsize::new(1);

fn socket_cookie(fd: c_int) -> Option<u64> {
    let mut cookie = 0u64;
    let mut length = std::mem::size_of::<u64>() as u32;
    // SAFETY: the kernel receives correctly sized, writable scalar storage.
    unsafe {
        raw::sys_getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            (&mut cookie as *mut u64).cast(),
            &mut length,
        )
    }
    .ok()?;
    (length as usize == std::mem::size_of::<u64>() && cookie != 0).then_some(cookie)
}

fn runtime() -> &'static QueueRuntime {
    let pid = raw::sys_getpid();
    loop {
        let current = RUNTIME.load(Ordering::Acquire);
        // SAFETY: a published runtime remains allocated for the process lifetime.
        if !current.is_null() && unsafe { (*current).pid == pid } {
            return unsafe { &*current };
        }
        let fresh = Box::into_raw(Box::new(QueueRuntime {
            pid,
            socket: AtomicI32::new(-1),
            socket_cookie: AtomicU64::new(0),
            helper_tid: AtomicI32::new(0),
            helper_start: Mutex::new(()),
            registrations: Mutex::new(artifact_hash_map()),
        }));
        match RUNTIME.compare_exchange(current, fresh, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                if !current.is_null() {
                    // A fork inherits neither the helper nor registrations.
                    // Never acquire or destroy a vanished thread's locks.
                    // Close the inherited socket only if it is still ours:
                    // child code may already have closed/reused its fd number.
                    // SAFETY: the inherited runtime remains allocated.
                    let old = unsafe { &*current };
                    let fd = old.socket.load(Ordering::Acquire);
                    let identity = old.socket_cookie.load(Ordering::Acquire);
                    if fd >= 0 && identity != 0 && socket_cookie(fd) == Some(identity) {
                        let _ = raw::sys_close(fd);
                    }
                }
                // SAFETY: fresh is now published and intentionally persistent.
                return unsafe { &*fresh };
            }
            Err(_) => {
                // SAFETY: this unpublished runtime owns no socket or helper.
                unsafe { drop(Box::from_raw(fresh)) };
            }
        }
    }
}

fn publish_helper(runtime: &QueueRuntime, state: c_int) {
    runtime.helper_tid.store(state, Ordering::Release);
    // SAFETY: the persistent runtime owns this aligned futex word.
    let _ = unsafe {
        raw::sys_futex(
            &runtime.helper_tid as *const AtomicI32 as *const u32,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            i32::MAX as u32,
            0,
            0,
            0,
        )
    };
}

unsafe extern "C-unwind" fn notification_start(argument: *mut c_void) -> *mut c_void {
    // Release all implementation ownership before application code can exit,
    // cancel, or register another notification from this callback.
    // SAFETY: a successful spawn transfers exactly this boxed Notice.
    let notice = *unsafe { Box::from_raw(argument.cast::<Notice>()) };
    // Null notification attributes use the current pthread defaults. Detach
    // here as well so a joinable default cannot retain completed callbacks.
    let _ = unsafe { crate::pthread_abi::pthread_detach(crate::pthread_abi::pthread_self()) };
    // GNU queue callbacks begin with all signals unblocked, including when the
    // supplied attribute contains a signal mask. Do not consume pending signals.
    let empty = 0u64;
    let _ = unsafe {
        raw::sys_rt_sigprocmask(
            libc::SIG_SETMASK,
            (&empty as *const u64).cast(),
            std::ptr::null_mut(),
            8,
        )
    };
    if let Notice::Thread { callback, value } = notice {
        // SAFETY: the registered callback accepts this original sigval. The
        // unwind ABI allows pthread_exit/cancellation through this entry frame.
        unsafe {
            callback(libc::sigval {
                sival_ptr: value as *mut c_void,
            })
        };
    }
    std::ptr::null_mut()
}

unsafe extern "C-unwind" fn helper_start(argument: *mut c_void) -> *mut c_void {
    // SAFETY: the published runtime outlives its detached receiver.
    let runtime = unsafe { &*argument.cast::<QueueRuntime>() };
    let cancel = unsafe { crate::pthread_abi::pthread_setcancelstate(1, std::ptr::null_mut()) };
    if cancel != 0 {
        publish_helper(runtime, -cancel);
        return std::ptr::null_mut();
    }
    publish_helper(runtime, raw::sys_gettid());
    let fd = runtime.socket.load(Ordering::Acquire);
    loop {
        let mut cookie = [0u8; COOKIE_LEN];
        // SAFETY: zero is valid initial storage for a kernel-written sockaddr.
        let mut peer: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut peer_len = std::mem::size_of_val(&peer) as u32;
        // MSG_TRUNC makes oversized datagrams distinguishable from a cookie.
        let received = unsafe {
            raw::sys_recvfrom(
                fd,
                cookie.as_mut_ptr(),
                cookie.len(),
                libc::MSG_TRUNC,
                (&mut peer as *mut libc::sockaddr_nl).cast(),
                &mut peer_len,
            )
        };
        match received {
            Err(libc::EINTR | libc::ENOBUFS) => continue,
            Err(error) => {
                let pending = {
                    let mut registrations = runtime
                        .registrations
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    publish_helper(runtime, -error);
                    std::mem::take(&mut *registrations)
                };
                drop(pending);
                return std::ptr::null_mut();
            }
            Ok(length) if length == COOKIE_LEN as isize => {}
            _ => continue,
        }
        if peer_len as usize != std::mem::size_of_val(&peer)
            || peer.nl_family != libc::AF_NETLINK as libc::sa_family_t
            || peer.nl_pid != 0
            || cookie[8..16] != *MAGIC
            || !matches!(cookie[COOKIE_LEN - 1], WOKEN_UP | REMOVED)
        {
            continue;
        }
        let mut token_bytes = [0u8; std::mem::size_of::<usize>()];
        token_bytes.copy_from_slice(&cookie[..std::mem::size_of::<usize>()]);
        let token = usize::from_ne_bytes(token_bytes);
        let registration = runtime
            .registrations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&token);
        let Some(registration) = registration else {
            continue;
        };
        if cookie[COOKIE_LEN - 1] == WOKEN_UP {
            let argument = Box::into_raw(Box::new(registration.notice));
            let attr = registration
                .attributes
                .as_ref()
                .map_or(std::ptr::null(), |attr| attr.as_ptr());
            // The registration keeps attributes alive through pthread_create.
            // No registry lock is held while creating or running a callback.
            if unsafe { aio_completion::spawn(notification_start, argument.cast(), attr) }.is_err()
            {
                // SAFETY: failed creation did not transfer this allocation.
                unsafe { drop(Box::from_raw(argument)) };
            }
        }
        // REMOVED drops the same owned snapshot without invoking user code.
    }
}

impl QueueRuntime {
    fn ensure_helper(&'static self) -> Result<c_int, c_int> {
        let _start = self.helper_start.lock().unwrap_or_else(|e| e.into_inner());
        let state = self.helper_tid.load(Ordering::Acquire);
        if state != 0 {
            return if state > 0 {
                Ok(self.socket.load(Ordering::Acquire))
            } else {
                Err(-state)
            };
        }
        let fd = raw::sys_socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0)?;
        self.socket.store(fd, Ordering::Release);
        self.socket_cookie
            .store(socket_cookie(fd).unwrap_or(0), Ordering::Release);
        // SAFETY: initialization establishes a live, local managed attribute.
        let mut attr: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
        let init = unsafe { crate::pthread_abi::pthread_attr_init(&mut attr) };
        let result = if init != 0 {
            Err(init)
        } else {
            let setup = (|| {
                let stack = unsafe {
                    crate::pthread_abi::pthread_attr_setstacksize(&mut attr, HELPER_STACK_SIZE)
                };
                if stack != 0 {
                    return Err(stack);
                }
                let detached = unsafe {
                    crate::pthread_abi::pthread_attr_setdetachstate(
                        &mut attr,
                        libc::PTHREAD_CREATE_DETACHED,
                    )
                };
                if detached != 0 {
                    return Err(detached);
                }
                // Block application signals before the helper enters user mode,
                // preserving NPTL cancellation/setxid signals 32 and 33.
                let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
                let bits = !((1u64 << 31) | (1u64 << 32));
                unsafe { std::ptr::write((&mut mask as *mut libc::sigset_t).cast::<u64>(), bits) };
                let masked =
                    unsafe { crate::pthread_abi::pthread_attr_setsigmask_np(&mut attr, &mask) };
                if masked != 0 {
                    return Err(masked);
                }
                unsafe {
                    aio_completion::spawn(
                        helper_start,
                        (self as *const Self).cast_mut().cast(),
                        &attr,
                    )
                }?;
                loop {
                    let state = self.helper_tid.load(Ordering::Acquire);
                    if state != 0 {
                        return if state > 0 { Ok(fd) } else { Err(-state) };
                    }
                    // SAFETY: the persistent runtime owns this aligned word.
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
            })();
            let _ = unsafe { crate::pthread_abi::pthread_attr_destroy(&mut attr) };
            setup
        };
        if result.is_err() {
            self.socket.store(-1, Ordering::Release);
            let _ = raw::sys_close(fd);
        }
        result
    }
}

pub(super) unsafe fn register(mqdes: c_int, event: *const libc::sigevent) -> Result<(), c_int> {
    // SAFETY: mq_notify's caller supplies a live event and attribute object.
    let (notice, attr) = unsafe { Notice::read(event) }?;
    let attributes = if attr.is_null() {
        None
    } else {
        Some(unsafe { NotificationThreadAttributes::for_mqueue(attr) }?)
    };
    let runtime = runtime();
    let fd = runtime.ensure_helper()?;
    let token = NEXT_TOKEN
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| libc::EAGAIN)?;
    let mut cookie = [0u8; COOKIE_LEN];
    cookie[..std::mem::size_of::<usize>()].copy_from_slice(&token.to_ne_bytes());
    cookie[8..16].copy_from_slice(MAGIC);
    // SAFETY: Linux copies this event and the complete cookie before returning.
    let mut kernel_event: libc::sigevent = unsafe { std::mem::zeroed() };
    kernel_event.sigev_notify = libc::SIGEV_THREAD;
    kernel_event.sigev_signo = fd;
    kernel_event.sigev_value.sival_ptr = cookie.as_mut_ptr().cast();
    {
        let mut registrations = runtime
            .registrations
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let state = runtime.helper_tid.load(Ordering::Acquire);
        if state <= 0 {
            return Err(if state < 0 { -state } else { libc::EAGAIN });
        }
        // Publish before registration can produce its first event. Linux may
        // wait for netlink receive-buffer space inside mq_notify, so release
        // this lock before entering the kernel: the receiver must keep draining
        // cookies even when several callers are registering concurrently.
        registrations.insert(token, Registration { notice, attributes });
    }
    let result =
        unsafe { raw::sys_mq_notify(mqdes, (&kernel_event as *const libc::sigevent) as usize) };
    if result.is_err() {
        let rejected = runtime
            .registrations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&token);
        // Attribute destruction has its own lock and stays outside the queue lock.
        drop(rejected);
    }
    result
}
