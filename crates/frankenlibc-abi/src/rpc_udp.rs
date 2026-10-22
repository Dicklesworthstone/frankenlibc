//! Native IPv4/Unix Sun RPC clients, shared with the portmapper v2 client.
//!
//! The public layouts follow glibc's LP64 rpc/clnt.h and rpc/auth.h. Wire
//! parsing is safe core code; procedure callbacks use the existing native XDR.
//! No host RPC resolution or borrowed socket flag mutation. Callbacks do not
//! run under a blocking lock; a nonblocking gate rejects reentrant operations.
//! A CLIENT must remain alive through all its operations. Concurrent destruction
//! or mutation of its public C fields is not made safe by the operation gate.

use super::{OpaqueAuth, Timeval, Xdr, XdrProc};
use std::cell::UnsafeCell;
use std::ffi::{c_char, c_int, c_uint, c_void};
use std::mem::{MaybeUninit, size_of};
use std::ptr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use frankenlibc_core::rpc::wire::{self, RemoteError, Reply};
use frankenlibc_core::syscall as raw;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

#[path = "rpc_tcp.rs"]
mod tcp;

// Reuse the same tracked-bound, fault-checked copier as the socket importers.
// Keep one implementation; do not introduce another process_vm/pipe fallback.
use crate::io_abi::iov_snapshot as user_copy;

const DEFAULT_BUFFER: usize = 8800;
const MAX_BUFFER: usize = 65536;
const MAX_STREAM_BUFFER: usize = 16 * 1024 * 1024;
const MAX_DATAGRAM: usize = 65507;
const SECOND: u64 = 1_000_000_000;
const RPC_SYSTEMERROR: c_int = 12;

#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct RpcError {
    status: c_int,
    padding: u32,
    // The C union is two u_longs, or an int/enum at its first address.
    // Bytes + explicit padding avoid copying uninitialized Rust struct padding.
    detail: [u8; 16],
}

impl RpcError {
    fn words(self) -> [u64; 2] {
        let parts = self.detail.as_chunks::<8>().0;
        [u64::from_ne_bytes(parts[0]), u64::from_ne_bytes(parts[1])]
    }

    fn status(status: c_int) -> Self {
        Self {
            status,
            padding: 0,
            detail: [0; 16],
        }
    }
    fn system(status: c_int, error: c_int) -> Self {
        let mut result = Self::status(status);
        result.detail[..4].copy_from_slice(&error.to_ne_bytes());
        result
    }
    fn remote(error: RemoteError) -> Self {
        let mut result = Self::status(error.status());
        match error {
            RemoteError::RpcVersion { low, high } | RemoteError::ProgramVersion { low, high } => {
                result.detail[..8].copy_from_slice(&(low as u64).to_ne_bytes());
                result.detail[8..].copy_from_slice(&(high as u64).to_ne_bytes());
            }
            RemoteError::Authentication(why) => {
                result.detail[..4].copy_from_slice(&why.to_ne_bytes())
            }
            _ => {}
        }
        result
    }
}

#[repr(C)]
struct CreateError {
    status: c_int,
    padding: u32,
    error: RpcError,
}

fn creation_error(status: c_int, error: RpcError) {
    let value = CreateError {
        status,
        padding: 0,
        error,
    };
    // SAFETY: the existing TLS accessor owns an aligned, initialized 32-byte slot.
    unsafe {
        super::__rpc_thread_createerr()
            .cast::<CreateError>()
            .write(value)
    };
}

pub(super) fn creation_status(status: c_int, error: c_int) {
    creation_error(status, RpcError::system(status, error));
}

pub(super) fn creation_error_details() -> (c_int, c_int, [u64; 2]) {
    // SAFETY: the public TLS accessor provides initialized, aligned storage
    // for this exact all-integer LP64 layout for the current thread.
    let value = unsafe { super::__rpc_thread_createerr().cast::<CreateError>().read() };
    (value.status, value.error.status, value.error.words())
}

fn kernel(raw_value: usize) -> Result<usize, c_int> {
    let value = raw_value as isize;
    if (-4095..0).contains(&value) {
        Err((-value) as c_int)
    } else {
        Ok(raw_value)
    }
}

unsafe fn import<T: Copy>(source: *const T) -> Result<T, RpcError> {
    let mut value = MaybeUninit::<T>::uninit();
    // SAFETY: destination has exactly sizeof(T) writable bytes. All uses of T
    // here are C integer/address/time structures with no invalid bit patterns.
    unsafe { user_copy::copy_user_bytes(source.cast(), value.as_mut_ptr().cast(), size_of::<T>()) }
        .map_err(|error| RpcError::system(RPC_SYSTEMERROR, error))?;
    Ok(unsafe { value.assume_init() })
}

unsafe fn publish<T>(value: &T, destination: *mut T) -> Result<(), RpcError> {
    // SAFETY: caller storage is only an address for the shared checked copier.
    // Published structures in this module have initialized fields and padding.
    unsafe {
        user_copy::copy_user_bytes(
            (value as *const T).cast(),
            destination.cast(),
            size_of::<T>(),
        )
    }
    .map_err(|error| RpcError::system(RPC_SYSTEMERROR, error))
}

fn buffer(size: usize) -> Result<Vec<u8>, RpcError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(size)
        .map_err(|_| RpcError::system(RPC_SYSTEMERROR, libc::ENOMEM))?;
    result.resize(size, 0);
    Ok(result)
}

fn boxed<T>(value: T) -> Result<Box<T>, RpcError> {
    let layout = std::alloc::Layout::new::<T>();
    if layout.size() == 0 {
        return Ok(Box::new(value));
    }
    // All callers use nonzero-sized CLIENT/state types. Box uses this allocator.
    let allocation = unsafe { std::alloc::alloc(layout) }.cast::<T>();
    if allocation.is_null() {
        return Err(RpcError::system(RPC_SYSTEMERROR, libc::ENOMEM));
    }
    unsafe {
        allocation.write(value);
        Ok(Box::from_raw(allocation))
    }
}

fn nanos(value: Timeval, nonzero: bool) -> Result<u64, RpcError> {
    if value.tv_sec < 0 || !(0..1_000_000).contains(&value.tv_usec) {
        return Err(RpcError::system(RPC_SYSTEMERROR, libc::EINVAL));
    }
    let result = (value.tv_sec as u64)
        .checked_mul(SECOND)
        .and_then(|seconds| seconds.checked_add(value.tv_usec as u64 * 1000))
        .filter(|&duration| !nonzero || duration != 0)
        .ok_or_else(|| RpcError::system(RPC_SYSTEMERROR, libc::EINVAL))?;
    Ok(result)
}

fn monotonic() -> Result<u64, RpcError> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: the kernel fills our owned timespec, without invoking ABI clock_gettime.
    kernel(unsafe {
        raw::syscall2(
            libc::SYS_clock_gettime as usize,
            libc::CLOCK_MONOTONIC as usize,
            (&mut time as *mut libc::timespec) as usize,
        )
    })
    .map_err(|error| RpcError::system(RPC_SYSTEMERROR, error))?;
    (time.tv_sec as u64)
        .checked_mul(SECOND)
        .and_then(|seconds| seconds.checked_add(time.tv_nsec as u64))
        .ok_or_else(|| RpcError::system(RPC_SYSTEMERROR, libc::EOVERFLOW))
}

/// One call budget shared by marshaling, credential refresh and transport IO.
/// A zero timeout permits only the existing nonblocking initial send behavior.
#[derive(Clone, Copy)]
struct Deadline {
    at: u64,
    nonblocking: bool,
}
impl Deadline {
    fn new(timeout: u64) -> Result<Self, RpcError> {
        let at = monotonic()?
            .checked_add(timeout)
            .ok_or_else(|| RpcError::system(RPC_SYSTEMERROR, libc::EINVAL))?;
        Ok(Self {
            at,
            nonblocking: timeout == 0,
        })
    }
    fn check(self) -> Result<(), RpcError> {
        if monotonic()? >= self.at {
            Err(RpcError::status(5))
        } else {
            Ok(())
        }
    }
}

struct Socket {
    fd: c_int,
    owned: bool,
}

impl Socket {
    fn open() -> Result<Self, RpcError> {
        // SAFETY: create one IPv4 datagram socket. No caller memory is submitted.
        let fd = kernel(unsafe {
            raw::syscall3(
                libc::SYS_socket as usize,
                libc::AF_INET as usize,
                (libc::SOCK_DGRAM | libc::SOCK_CLOEXEC) as usize,
                0,
            )
        })
        .map_err(|error| RpcError::system(RPC_SYSTEMERROR, error))? as c_int;
        Ok(Self { fd, owned: true })
    }
    fn borrow(fd: c_int) -> Result<Self, RpcError> {
        for (option, expected) in [
            (libc::SO_TYPE, libc::SOCK_DGRAM),
            (libc::SO_DOMAIN, libc::AF_INET),
        ] {
            let mut value: c_int = 0;
            let mut length = size_of::<c_int>() as libc::socklen_t;
            // SAFETY: both result pointers name initialized owned scalars.
            kernel(unsafe {
                raw::syscall5(
                    libc::SYS_getsockopt as usize,
                    fd as usize,
                    libc::SOL_SOCKET as usize,
                    option as usize,
                    (&mut value as *mut c_int) as usize,
                    (&mut length as *mut libc::socklen_t) as usize,
                )
            })
            .map_err(|error| RpcError::system(RPC_SYSTEMERROR, error))?;
            if length as usize != size_of::<c_int>() || value != expected {
                return Err(RpcError::system(RPC_SYSTEMERROR, libc::EPROTOTYPE));
            }
        }
        Ok(Self { fd, owned: false })
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: exactly this object owns fd, including descriptor zero.
            // Never retry close(EINTR), and never replace the RPC error with errno.
            unsafe { raw::syscall1(libc::SYS_close as usize, self.fd as usize) };
        }
    }
}

fn transaction_id() -> u32 {
    static SEED: OnceLock<u32> = OnceLock::new();
    static SERIAL: AtomicU32 = AtomicU32::new(0);
    let seed = *SEED.get_or_init(|| {
        let mut bytes = [0u8; 4];
        if raw::sys_getrandom_slice(&mut bytes, libc::GRND_NONBLOCK) == Ok(4) {
            u32::from_ne_bytes(bytes)
        } else {
            // XIDs correlate replies; they do not authenticate peers. Entropy
            // failure must not prevent ordinary RPC service availability.
            let pid = unsafe { raw::syscall0(libc::SYS_getpid as usize) } as u32;
            pid.rotate_left(16) ^ monotonic().unwrap_or(0) as u32
        }
    });
    seed.wrapping_add(SERIAL.fetch_add(1, Ordering::Relaxed))
}

/// Retransmit identical bytes, bounded by a single monotonic deadline. A flood
/// of unrelated replies or repeated EINTR never starts a fresh timeout period.
fn exchange(
    socket: &Socket,
    peer: &libc::sockaddr_in,
    request: &[u8],
    response: &mut [u8],
    xid: u32,
    retry: u64,
    timeout: u64,
) -> Result<usize, RpcError> {
    exchange_until(
        socket,
        peer,
        request,
        response,
        xid,
        retry,
        Deadline::new(timeout)?,
    )
}

fn exchange_until(
    socket: &Socket,
    peer: &libc::sockaddr_in,
    request: &[u8],
    response: &mut [u8],
    xid: u32,
    retry: u64,
    budget: Deadline,
) -> Result<usize, RpcError> {
    if request.len() > MAX_DATAGRAM {
        return Err(RpcError::system(1, libc::EMSGSIZE));
    }
    let start = monotonic()?;
    let deadline = budget.at;
    let mut next_send = start;
    let mut waiting_to_send = false;
    let mut first_send = true;
    loop {
        let now = monotonic()?;
        if (!first_send || !budget.nonblocking) && now >= deadline {
            return Err(RpcError::status(5));
        }
        if first_send || now >= next_send || waiting_to_send {
            first_send = false;
            // SAFETY: request and peer are live owned/borrowed Rust storage.
            let sent = kernel(unsafe {
                raw::syscall6(
                    libc::SYS_sendto as usize,
                    socket.fd as usize,
                    request.as_ptr() as usize,
                    request.len(),
                    (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as usize,
                    (peer as *const libc::sockaddr_in) as usize,
                    size_of::<libc::sockaddr_in>(),
                )
            });
            match sent {
                Ok(length) if length == request.len() => {
                    waiting_to_send = false;
                    next_send = now.saturating_add(retry);
                }
                Ok(_) => return Err(RpcError::system(3, libc::EIO)),
                Err(libc::EINTR) => continue,
                Err(libc::EAGAIN) => waiting_to_send = true,
                Err(error) => return Err(RpcError::system(3, error)),
            }
        }
        let now = monotonic()?;
        if now >= deadline {
            return Err(RpcError::status(5));
        }
        let wake = if waiting_to_send {
            deadline
        } else {
            deadline.min(next_send)
        };
        let remaining = wake.saturating_sub(now);
        let mut interval = libc::timespec {
            tv_sec: (remaining / SECOND) as libc::time_t,
            tv_nsec: (remaining % SECOND) as libc::c_long,
        };
        let mut pollfd = libc::pollfd {
            fd: socket.fd,
            events: libc::POLLIN | if waiting_to_send { libc::POLLOUT } else { 0 },
            revents: 0,
        };
        // SAFETY: ppoll reads/writes only our stack objects. Null signal mask
        // preserves the caller's mask; MSG_DONTWAIT avoids changing shared fd flags.
        let ready = kernel(unsafe {
            raw::syscall5(
                libc::SYS_ppoll as usize,
                (&mut pollfd as *mut libc::pollfd) as usize,
                1,
                (&mut interval as *mut libc::timespec) as usize,
                0,
                8,
            )
        });
        match ready {
            Err(libc::EINTR) | Ok(0) => continue,
            Err(error) => return Err(RpcError::system(4, error)),
            Ok(_) => {}
        }
        if pollfd.revents & libc::POLLNVAL != 0 {
            return Err(RpcError::system(4, libc::EBADF));
        }
        if pollfd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) == 0 {
            continue;
        }
        let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut from_length = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: all three destinations are owned and have their true extents.
        let received = kernel(unsafe {
            raw::syscall6(
                libc::SYS_recvfrom as usize,
                socket.fd as usize,
                response.as_mut_ptr() as usize,
                response.len(),
                (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as usize,
                (&mut from as *mut libc::sockaddr_in) as usize,
                (&mut from_length as *mut libc::socklen_t) as usize,
            )
        });
        let length = match received {
            Err(libc::EINTR) | Err(libc::EAGAIN) => continue,
            Err(error) => return Err(RpcError::system(4, error)),
            Ok(length) => length,
        };
        if from_length as usize != size_of::<libc::sockaddr_in>()
            || from.sin_family != peer.sin_family
            || from.sin_addr.s_addr != peer.sin_addr.s_addr
            || from.sin_port != peer.sin_port
        {
            continue;
        }
        if length < 4
            || response.len() < 4
            || u32::from_be_bytes([response[0], response[1], response[2], response[3]]) != xid
        {
            continue;
        }
        if length > response.len() {
            return Err(RpcError::system(2, libc::EMSGSIZE));
        }
        // Account for scheduling delay while processing readiness, too.
        if monotonic()? >= deadline {
            return Err(RpcError::status(5));
        }
        return Ok(length);
    }
}

#[repr(C)]
struct Auth {
    credential: OpaqueAuth,
    verifier: OpaqueAuth,
    key: [u8; 8],
    operations: *const AuthOps,
    private: *mut c_void,
}
#[repr(C)]
struct AuthOps {
    next: unsafe extern "C" fn(*mut Auth),
    marshal: unsafe extern "C" fn(*mut Auth, *mut Xdr) -> c_int,
    validate: unsafe extern "C" fn(*mut Auth, *mut OpaqueAuth) -> c_int,
    refresh: unsafe extern "C" fn(*mut Auth) -> c_int,
    destroy: unsafe extern "C" fn(*mut Auth),
}
#[path = "rpc_auth_unix.rs"]
mod auth_unix;
pub(super) use auth_unix::{create as authunix_create, create_default as authunix_create_default};

unsafe extern "C" fn none_noop(_: *mut Auth) {}
unsafe extern "C" fn none_marshal(_: *mut Auth, xdr: *mut Xdr) -> c_int {
    let mut word = 0;
    for _ in 0..4 {
        if unsafe { super::xdr_u_int(xdr.cast(), &mut word) } == 0 {
            return 0;
        }
    }
    1
}
unsafe extern "C" fn none_validate(_: *mut Auth, _: *mut OpaqueAuth) -> c_int {
    1
}
unsafe extern "C" fn none_refresh(_: *mut Auth) -> c_int {
    0
}
static NONE_OPS: AuthOps = AuthOps {
    next: none_noop,
    marshal: none_marshal,
    validate: none_validate,
    refresh: none_refresh,
    destroy: none_noop,
};
struct SharedAuth(UnsafeCell<Auth>);
// SAFETY: Rust never mutates the process-lifetime AUTH_NONE object after static
// initialization. Its callbacks ignore its public fields; concurrent external
// writes remain the C caller's responsibility, as for glibc's singleton AUTH.
unsafe impl Sync for SharedAuth {}
static NONE: SharedAuth = SharedAuth(UnsafeCell::new(Auth {
    credential: OpaqueAuth {
        oa_flavor: 0,
        oa_base: ptr::null_mut(),
        oa_length: 0,
    },
    verifier: OpaqueAuth {
        oa_flavor: 0,
        oa_base: ptr::null_mut(),
        oa_length: 0,
    },
    key: [0; 8],
    operations: &NONE_OPS,
    private: ptr::null_mut(),
}));
pub(super) fn authnone() -> *mut c_void {
    NONE.0.get().cast()
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Client {
    auth: *mut Auth,
    operations: *const ClientOps,
    private: *mut State,
}
#[repr(C)]
struct ClientOps {
    call: unsafe extern "C-unwind" fn(
        *mut Client,
        u64,
        Option<XdrProc>,
        *mut c_void,
        Option<XdrProc>,
        *mut c_void,
        Timeval,
    ) -> c_int,
    abort: unsafe extern "C" fn(),
    geterr: unsafe extern "C" fn(*mut Client, *mut RpcError),
    freeres: unsafe extern "C-unwind" fn(*mut Client, Option<XdrProc>, *mut c_void) -> c_int,
    destroy: unsafe extern "C" fn(*mut Client),
    control: unsafe extern "C" fn(*mut Client, c_int, *mut c_char) -> c_int,
}
struct State {
    busy: AtomicBool,
    data: UnsafeCell<Data>,
}
struct Data {
    socket: Socket,
    stream: Option<tcp::Stream>,
    peer: libc::sockaddr_in,
    unix_peer: Option<libc::sockaddr_un>,
    program: u32,
    version: u32,
    xid: u32,
    next_xid: Option<u32>,
    retry: Timeval,
    timeout: Option<Timeval>,
    send: Vec<u8>,
    receive: Vec<u8>,
    error: RpcError,
}
struct Gate<'a>(&'a State);
impl<'a> Gate<'a> {
    fn enter(state: &'a State) -> Option<Self> {
        state
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(Self(state))
    }
}
impl Drop for Gate<'_> {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
    }
}

#[path = "rpc_call.rs"]
mod invocation;
use invocation::invoke;

unsafe extern "C-unwind" fn call(
    client: *mut Client,
    procedure: u64,
    arguments: Option<XdrProc>,
    argument: *mut c_void,
    results: Option<XdrProc>,
    result: *mut c_void,
    timeout: Timeval,
) -> c_int {
    // SAFETY: CLIENT and private state are live for the C call's duration.
    let state = unsafe { &*(*client).private };
    let Some(_gate) = Gate::enter(state) else {
        return RPC_SYSTEMERROR;
    };
    let data = unsafe { &mut *state.data.get() };
    let (_, decision) = super::runtime_policy::decide(
        ApiFamily::Socket,
        data.socket.fd as usize,
        data.send.len(),
        false,
        true,
        0,
    );
    let outcome = if matches!(decision.action, MembraneAction::Deny) {
        Err(RpcError::system(RPC_SYSTEMERROR, libc::EACCES))
    } else {
        unsafe {
            invoke(
                client, data, procedure, arguments, argument, results, result, timeout,
            )
        }
    };
    data.error = outcome.err().unwrap_or_else(|| RpcError::status(0));
    super::runtime_policy::observe(
        ApiFamily::Socket,
        decision.profile,
        100,
        data.error.status != 0,
    );
    data.error.status
}
unsafe extern "C" fn abort() {}

/// Snapshot any live public CLIENT through its own geterr operation. A
/// foreign CLIENT need not use our private State or have non-null unrelated
/// operations. Do not hold an owned diagnostic-buffer lock over the callback.
pub(super) unsafe fn client_error(client: *mut c_void) -> Result<(c_int, [u64; 2]), c_int> {
    if client.is_null() {
        return Err(libc::EINVAL);
    }
    // SAFETY: import fault-checks the address and Client contains only raw
    // pointers, so every imported bit pattern is valid as an opaque header.
    let header = unsafe { import::<Client>(client.cast()) }.map_err(|_| libc::EFAULT)?;
    if header.operations.is_null() {
        return Err(libc::EINVAL);
    }
    // Use integer arithmetic for an untrusted table address and import only
    // the one slot: a foreign table can have NULL in its other function slots.
    let slot = (header.operations as usize)
        .checked_add(std::mem::offset_of!(ClientOps, geterr))
        .ok_or(libc::EFAULT)?;
    // SAFETY: import fault-checks this one integer-sized slot, without
    // constructing function pointers from the table's unrelated NULL slots.
    let operation = unsafe { import::<usize>(slot as *const usize) }.map_err(|_| libc::EFAULT)?;
    if operation == 0 {
        return Err(libc::EINVAL);
    }
    // SAFETY: a live CLIENT supplies a callable public geterr slot. C-unwind
    // preserves application exceptions/pthread_exit across this boundary.
    let operation: unsafe extern "C-unwind" fn(*mut Client, *mut RpcError) =
        unsafe { std::mem::transmute(operation) };
    let mut error = RpcError::system(RPC_SYSTEMERROR, libc::EINVAL);
    // SAFETY: the caller keeps the public CLIENT/callback live; error is a
    // writable, fully initialized rpc_err for the duration of the callback.
    unsafe { operation(client.cast(), &mut error) };
    Ok((error.status, error.words()))
}

unsafe extern "C" fn geterr(client: *mut Client, output: *mut RpcError) {
    let state = unsafe { &*(*client).private };
    let error = if let Some(_gate) = Gate::enter(state) {
        unsafe { (*state.data.get()).error }
    } else {
        RpcError::system(RPC_SYSTEMERROR, libc::EBUSY)
    };
    let _ = unsafe { publish(&error, output) };
}
unsafe extern "C-unwind" fn freeres(
    client: *mut Client,
    callback: Option<XdrProc>,
    result: *mut c_void,
) -> c_int {
    let state = unsafe { &*(*client).private };
    let Some(_gate) = Gate::enter(state) else {
        return 0;
    };
    let Some(callback) = callback else {
        return 0;
    };
    let mut xdr: Xdr = unsafe { std::mem::zeroed() };
    xdr.x_op = super::XDR_FREE;
    // SAFETY: the callback has the public XDR ABI; permit foreign exceptions
    // and forced pthread unwinds to release the operation gate.
    let callback: unsafe extern "C-unwind" fn(*mut c_void, *mut c_void) -> c_int =
        unsafe { std::mem::transmute(callback) };
    unsafe { callback((&mut xdr as *mut Xdr).cast(), result) }
}
unsafe extern "C" fn destroy(client: *mut Client) {
    let state = unsafe { (*client).private };
    if unsafe {
        (*state)
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
    }
    .is_err()
    {
        // A callback cannot invalidate the outer call's live buffers/state.
        unsafe { super::set_abi_errno(libc::EBUSY) };
        return;
    }
    // User-installed authenticators are caller-owned. AUTH_NONE is immortal.
    unsafe {
        drop(Box::from_raw(state));
        drop(Box::from_raw(client));
    }
}
unsafe extern "C" fn control(
    client: *mut Client,
    request: c_int,
    information: *mut c_char,
) -> c_int {
    let state = unsafe { &*(*client).private };
    let Some(_gate) = Gate::enter(state) else {
        return 0;
    };
    let data = unsafe { &mut *state.data.get() };
    // Retransmission timers are a datagram-only operation. Never pretend a
    // reliable stream will retransmit an application request after a timeout.
    if data.stream.is_some() && matches!(request, 4 | 5) {
        return 0;
    }
    let outcome: Result<(), RpcError> = (|| {
        match request {
            1 | 4 => {
                let value = unsafe { import::<Timeval>(information.cast()) }?;
                nanos(value, request == 4)?;
                if request == 1 {
                    data.timeout = Some(value);
                } else {
                    data.retry = value;
                }
            }
            2 => unsafe {
                publish(
                    &data.timeout.unwrap_or(Timeval {
                        tv_sec: -1,
                        tv_usec: -1,
                    }),
                    information.cast(),
                )
            }?,
            3 => {
                if let Some(peer) = &data.unix_peer {
                    // SAFETY: publish fault-checks the complete Unix address.
                    unsafe { publish(peer, information.cast()) }?;
                } else {
                    // SAFETY: IPv4 retains its original 16-byte control ABI.
                    unsafe { publish(&data.peer, information.cast()) }?;
                }
            }
            5 => unsafe { publish(&data.retry, information.cast()) }?,
            6 => unsafe { publish(&data.socket.fd, information.cast()) }?,
            8 => data.socket.owned = true,
            9 => data.socket.owned = false,
            // The LP64 glibc controls use u_long, even though RPC wire words are 32-bit.
            10 => unsafe { publish(&(data.xid as u64), information.cast()) }?,
            11 => {
                let next = unsafe { import::<u64>(information.cast()) }? as u32;
                data.xid = next.wrapping_sub(1);
                // GNU's Unix client decrements the serialized word after
                // CLSET_XID prepares htonl(next - 1). Preserve that observable
                // Unix control behavior without changing IPv4 clients.
                data.next_xid = Some(if data.unix_peer.is_some() {
                    u32::from_be(next.wrapping_sub(1).to_be().wrapping_sub(1))
                } else {
                    next
                });
            }
            12 => unsafe { publish(&(data.version as u64), information.cast()) }?,
            13 => data.version = unsafe { import::<u64>(information.cast()) }? as u32,
            14 => unsafe { publish(&(data.program as u64), information.cast()) }?,
            15 => data.program = unsafe { import::<u64>(information.cast()) }? as u32,
            _ => return Err(RpcError::system(RPC_SYSTEMERROR, libc::EINVAL)),
        }
        Ok(())
    })();
    if outcome.is_ok() { 1 } else { 0 }
}
static CLIENT_OPS: ClientOps = ClientOps {
    call,
    abort,
    geterr,
    freeres,
    destroy,
    control,
};

/// One-shot convenience calls own their freshly constructed client. Keep the
/// callback casts and the matching destruction in the CLIENT implementation.
pub(super) unsafe fn call_once(
    client: *mut c_void,
    procedure: u64,
    arguments: Option<XdrProc>,
    argument: *mut c_void,
    results: Option<XdrProc>,
    result: *mut c_void,
) -> c_int {
    struct OwnedClient(*mut Client);
    impl Drop for OwnedClient {
        fn drop(&mut self) {
            // SAFETY: this guard owns the freshly constructed client. The
            // inner operation gate drops before normal or foreign unwinding
            // reaches here, so destruction can release its socket and buffers.
            unsafe { destroy(self.0) };
        }
    }
    let client = OwnedClient(client.cast());
    unsafe {
        call(
            client.0,
            procedure,
            arguments,
            argument,
            results,
            result,
            Timeval {
                tv_sec: 25,
                tv_usec: 0,
            },
        )
    }
}

struct CreateFailure {
    status: c_int,
    error: RpcError,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Network {
    Datagram,
    Tcp,
    Unix,
}
impl From<RpcError> for CreateFailure {
    fn from(error: RpcError) -> Self {
        Self {
            status: error.status,
            error,
        }
    }
}
impl CreateFailure {
    fn portmapper(error: RpcError) -> Self {
        Self {
            status: if error.status == 15 { 15 } else { 14 },
            error,
        }
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn make_client(
    address: *mut c_void,
    program: u64,
    version: u64,
    retry: Timeval,
    descriptor: *mut c_int,
    sendsize: c_uint,
    recvsize: c_uint,
    network: Network,
) -> Result<*mut c_void, CreateFailure> {
    nanos(retry, true)?;
    let stream = network != Network::Datagram;
    let unix_peer = if network == Network::Unix {
        // SAFETY: import copies the complete public sockaddr_un with faults checked.
        let peer = unsafe { import::<libc::sockaddr_un>(address.cast()) }?;
        if peer.sun_family as c_int != libc::AF_UNIX {
            return Err(RpcError::system(RPC_SYSTEMERROR, libc::EAFNOSUPPORT).into());
        }
        Some(peer)
    } else {
        None
    };
    let mut peer = if unix_peer.is_some() {
        // SAFETY: the unused IPv4 fields have a valid initialized zero representation.
        unsafe { std::mem::zeroed() }
    } else {
        // SAFETY: the shared importer bounds and fault-checks the IPv4 input.
        unsafe { import::<libc::sockaddr_in>(address.cast()) }?
    };
    let fd = unsafe { import(descriptor.cast_const()) }?;
    if unix_peer.is_none() && peer.sin_family as c_int != libc::AF_INET {
        return Err(RpcError::system(RPC_SYSTEMERROR, libc::EAFNOSUPPORT).into());
    }
    let original_port = peer.sin_port;
    if unix_peer.is_none() && peer.sin_port == 0 {
        let protocol = if stream {
            libc::IPPROTO_TCP
        } else {
            libc::IPPROTO_UDP
        };
        let port = portmap(&peer, program, version, protocol as u32, 0, 3)
            .map_err(CreateFailure::portmapper)?;
        peer.sin_port = port.to_be();
    }
    let size = |requested: c_uint, minimum: usize| -> Result<usize, RpcError> {
        let requested = if requested == 0 {
            DEFAULT_BUFFER
        } else {
            requested as usize
        };
        let maximum = if stream {
            MAX_STREAM_BUFFER
        } else {
            MAX_BUFFER
        };
        let rounded = requested
            .checked_add(3)
            .map(|n| n & !3)
            .filter(|&n| n >= minimum && n <= maximum)
            .ok_or_else(|| RpcError::system(RPC_SYSTEMERROR, libc::EINVAL))?;
        Ok(rounded)
    };
    let send = buffer(size(sendsize, wire::NULL_CALL_BYTES)?)?;
    let receive = buffer(size(recvsize, 24)?)?;
    let socket = if let Some(peer) = &unix_peer {
        tcp::connect_unix(peer, fd)?
    } else if stream {
        tcp::connect(&peer, fd)?
    } else if fd == -1 {
        Socket::open()?
    } else {
        Socket::borrow(fd)?
    };
    let stream = stream.then(|| {
        let mut transport = tcp::Stream::new(receive.len());
        transport.unix = unix_peer.is_some();
        transport
    });
    let returned_fd = socket.fd;
    let state = boxed(State {
        busy: AtomicBool::new(false),
        data: UnsafeCell::new(Data {
            socket,
            stream,
            peer,
            unix_peer,
            program: program as u32,
            version: version as u32,
            xid: transaction_id(),
            next_xid: None,
            retry,
            timeout: None,
            send,
            receive,
            error: RpcError::status(0),
        }),
    })?;
    let client = boxed(Client {
        auth: authnone().cast(),
        operations: &CLIENT_OPS,
        private: (&*state as *const State).cast_mut(),
    })?;
    if unix_peer.is_none() && original_port == 0 {
        let port_pointer = unsafe {
            address
                .cast::<u8>()
                .add(std::mem::offset_of!(libc::sockaddr_in, sin_port))
                .cast()
        };
        unsafe { publish(&peer.sin_port, port_pointer) }?;
    }
    if fd == -1 || (unix_peer.is_some() && fd < 0) {
        unsafe { publish(&returned_fd, descriptor) }?;
    }
    // Ownership leaves these two Boxes only after every fallible operation.
    let _ = Box::into_raw(state);
    Ok(Box::into_raw(client).cast())
}

pub(super) unsafe fn create(
    address: *mut c_void,
    program: u64,
    version: u64,
    retry: Timeval,
    descriptor: *mut c_int,
    sendsize: c_uint,
    recvsize: c_uint,
) -> *mut c_void {
    unsafe {
        create_transport(
            address,
            program,
            version,
            retry,
            descriptor,
            sendsize,
            recvsize,
            Network::Datagram,
        )
    }
}

pub(super) unsafe fn create_tcp(
    address: *mut c_void,
    program: u64,
    version: u64,
    descriptor: *mut c_int,
    sendsize: c_uint,
    recvsize: c_uint,
) -> *mut c_void {
    unsafe {
        create_transport(
            address,
            program,
            version,
            Timeval {
                tv_sec: 1,
                tv_usec: 0,
            },
            descriptor,
            sendsize,
            recvsize,
            Network::Tcp,
        )
    }
}

pub(super) unsafe fn create_unix(
    address: *mut c_void,
    program: u64,
    version: u64,
    descriptor: *mut c_int,
    sendsize: c_uint,
    recvsize: c_uint,
) -> *mut c_void {
    // SAFETY: the common constructor imports all public buffers with fault checks.
    unsafe {
        create_transport(
            address,
            program,
            version,
            Timeval {
                tv_sec: 1,
                tv_usec: 0,
            },
            descriptor,
            sendsize,
            recvsize,
            Network::Unix,
        )
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_transport(
    address: *mut c_void,
    program: u64,
    version: u64,
    retry: Timeval,
    descriptor: *mut c_int,
    sendsize: c_uint,
    recvsize: c_uint,
    network: Network,
) -> *mut c_void {
    let (_, decision) =
        super::runtime_policy::decide(ApiFamily::Socket, address as usize, 0, false, true, 0);
    let result = if matches!(decision.action, MembraneAction::Deny) {
        Err(CreateFailure::from(RpcError::system(
            RPC_SYSTEMERROR,
            libc::EACCES,
        )))
    } else {
        unsafe {
            make_client(
                address, program, version, retry, descriptor, sendsize, recvsize, network,
            )
        }
    };
    super::runtime_policy::observe(ApiFamily::Socket, decision.profile, 100, result.is_err());
    match result {
        Ok(client) => client,
        Err(error) => {
            if network == Network::Unix && error.status == RPC_SYSTEMERROR {
                // GNU Unix creation writes cf_stat and re_errno only. The
                // caller-visible nested status/union tail retain their prior
                // TLS values, including values installed by a previous error.
                // SAFETY: this accessor supplies the current thread's live,
                // initialized and aligned public 32-byte create-error record.
                unsafe {
                    let slot = super::__rpc_thread_createerr().cast::<CreateError>();
                    (*slot).status = error.status;
                    (*slot).error.detail[..4].copy_from_slice(&error.error.detail[..4]);
                }
            } else {
                creation_error(error.status, error.error);
            }
            ptr::null_mut()
        }
    }
}

/// Execute one portmapper v2 mapping request over the shared deadline-bounded retry loop.
/// A zero GETPORT result is a semantic failure, not a valid endpoint.
fn portmap(
    peer: &libc::sockaddr_in,
    program: u64,
    version: u64,
    protocol: u32,
    port: u16,
    procedure: u32,
) -> Result<u16, RpcError> {
    // Mapping arguments use GNU xdr_u_long, which rejects values outside the
    // 32-bit wire domain. Do not turn an invalid LP64 identifier into a query
    // for a different, truncated program or version.
    let program = u32::try_from(program).map_err(|_| RpcError::status(1))?;
    let version = u32::try_from(version).map_err(|_| RpcError::status(1))?;
    let mut endpoint = *peer;
    endpoint.sin_port = 111u16.to_be();
    let mut arguments = [0u8; 16];
    for (slot, word) in
        arguments
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip([program, version, protocol, port as u32])
    {
        *slot = word.to_be_bytes();
    }
    let mut request = [0u8; 56];
    let xid = transaction_id();
    wire::encode_null_call(&mut request, xid, 100000, 2, procedure, &arguments)
        .map_err(|_| RpcError::status(1))?;
    let mut response = [0u8; 1024];
    let length = if procedure == 3 && protocol == libc::IPPROTO_TCP as u32 {
        // GNU TCP discovery consults the mapper over TCP too. Reuse the
        // bounded native record transport without recursively constructing a
        // CLIENT or falling back to UDP when TCP is unavailable.
        let socket = tcp::connect(&endpoint, -1)?;
        let mut stream = tcp::Stream::new(response.len());
        stream.exchange(
            &socket,
            &request,
            &mut response,
            xid,
            Deadline::new(60 * SECOND)?,
        )?
    } else {
        let socket = Socket::open()?;
        exchange(
            &socket,
            &endpoint,
            &request,
            &mut response,
            xid,
            5 * SECOND,
            60 * SECOND,
        )?
    };
    let result =
        match wire::decode_reply(&response[..length], xid).map_err(|_| RpcError::status(2))? {
            Reply::Failure(error) => return Err(RpcError::remote(error)),
            Reply::Success { results, .. } if results.len() == 4 => &response[results],
            _ => return Err(RpcError::status(2)),
        };
    let value = u32::from_be_bytes([result[0], result[1], result[2], result[3]]);
    if procedure == 3 {
        if value == 0 {
            return Err(RpcError::status(15));
        }
        u16::try_from(value).map_err(|_| RpcError::status(2))
    } else if value <= 1 {
        Ok(value as u16)
    } else {
        Err(RpcError::status(2))
    }
}

pub(super) unsafe fn getport(
    address: *mut c_void,
    program: u64,
    version: u64,
    protocol: c_uint,
) -> u16 {
    let (_, decision) =
        super::runtime_policy::decide(ApiFamily::Socket, address as usize, 0, false, true, 0);
    let result = if matches!(decision.action, MembraneAction::Deny) {
        Err(RpcError::system(RPC_SYSTEMERROR, libc::EACCES))
    } else {
        (|| {
            let peer = unsafe { import::<libc::sockaddr_in>(address.cast()) }?;
            if peer.sin_family as c_int != libc::AF_INET {
                return Err(RpcError::system(RPC_SYSTEMERROR, libc::EAFNOSUPPORT));
            }
            let result = portmap(&peer, program, version, protocol, 0, 3);
            // Public pmap_getport resets the caller's port on return (including a
            // zero/unregistered result). Constructors instead publish the discovered
            // service port. Keep those two ABI contracts distinct.
            let port_pointer = unsafe {
                address
                    .cast::<u8>()
                    .add(std::mem::offset_of!(libc::sockaddr_in, sin_port))
                    .cast()
            };
            unsafe { publish(&0u16, port_pointer) }?;
            result
        })()
    };
    super::runtime_policy::observe(ApiFamily::Socket, decision.profile, 100, result.is_err());
    match result {
        Ok(port) => port,
        Err(error) => {
            creation_error(if error.status == 15 { 15 } else { 14 }, error);
            0
        }
    }
}

pub(super) fn registration(
    program: u64,
    version: u64,
    protocol: c_int,
    port: u16,
    remove: bool,
) -> c_int {
    let peer = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    let (_, decision) = super::runtime_policy::decide(ApiFamily::Socket, 0, 0, false, true, 0);
    let result = if matches!(decision.action, MembraneAction::Deny) {
        Err(RpcError::system(RPC_SYSTEMERROR, libc::EACCES))
    } else {
        portmap(
            &peer,
            program,
            version,
            protocol as u32,
            port,
            if remove { 2 } else { 1 },
        )
    };
    super::runtime_policy::observe(ApiFamily::Socket, decision.profile, 100, result.is_err());
    match result {
        Ok(value) => value as c_int,
        Err(error) => {
            creation_error(14, error);
            0
        }
    }
}
