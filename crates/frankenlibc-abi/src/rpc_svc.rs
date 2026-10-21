//! Native glibc Sun RPC UDP services. RFC 5531 envelopes live in safe core.
//!
//! Registry locks never cover callbacks or socket I/O. A registry Arc retains
//! each transport while a dispatch/XDR operation runs; destroying it inside a
//! callback unregisters immediately, but closes/frees only after those owners
//! leave. Nonblocking operation gates reject recursive use of one XDR buffer.
//! This is the glibc LP64 interface, not libtirpc's differently shaped SVCXPRT.

use super::rpc_svc_cache::{CacheError, Peer, ReplyCache};
use super::{AcceptedReply, AuthUnixParms, OpaqueAuth, RejectedReply, Xdr};
use frankenlibc_core::rpc::wire::{
    RemoteError,
    service::{self, Call, CallError},
};
use frankenlibc_core::syscall as raw;
use std::cell::UnsafeCell;
use std::ffi::{c_int, c_uint, c_void};
use std::mem::{size_of, zeroed};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

const LIMIT: usize = libc::FD_SETSIZE;
const DEFAULT_BUFFER: usize = 8800;
const MAX_BUFFER: usize = 65536;
type Procedure = unsafe extern "C-unwind" fn(*mut c_void, *mut c_void) -> c_int;
type Dispatch = unsafe extern "C-unwind" fn(*mut ServiceRequest, *mut SvcXprt);

#[repr(C)]
struct SvcOps {
    recv: unsafe extern "C-unwind" fn(*mut SvcXprt, *mut c_void) -> c_int,
    stat: unsafe extern "C" fn(*mut SvcXprt) -> c_int,
    getargs: unsafe extern "C-unwind" fn(*mut SvcXprt, *mut c_void, *mut c_void) -> c_int,
    reply: unsafe extern "C-unwind" fn(*mut SvcXprt, *mut c_void) -> c_int,
    freeargs: unsafe extern "C-unwind" fn(*mut SvcXprt, *mut c_void, *mut c_void) -> c_int,
    destroy: unsafe extern "C" fn(*mut SvcXprt),
}

#[repr(C)]
struct SvcXprt {
    sock: c_int,
    port: u16,
    ops: *const SvcOps,
    addrlen: c_int,
    raddr: libc::sockaddr_in,
    verifier: OpaqueAuth,
    private1: *mut c_void,
    private2: *mut c_void,
    padding: [u8; 256],
}

#[repr(C)]
struct ServiceRequest {
    program: u64,
    version: u64,
    procedure: u64,
    credential: OpaqueAuth,
    cooked: *mut c_void,
    transport: *mut SvcXprt,
}

#[repr(C)]
struct CallMessage {
    xid: u64,
    direction: c_int,
    rpc_version: u64,
    program: u64,
    version: u64,
    procedure: u64,
    credential: OpaqueAuth,
    verifier: OpaqueAuth,
}

/// glibc reserves 400 bytes for rq_clntcred. Pointers in params refer into
/// this caller-owned area, never into a temporary authentication stack frame.
#[repr(C)]
struct CookedCredential {
    params: AuthUnixParms,
    machine: [u8; 256],
    groups: [u32; 16],
}

const _: () = {
    assert!(size_of::<SvcXprt>() == 336);
    assert!(std::mem::offset_of!(SvcXprt, verifier) == 40);
    assert!(size_of::<ServiceRequest>() == 64);
    assert!(size_of::<CallMessage>() == 96);
    assert!(std::mem::offset_of!(CallMessage, credential) == 48);
    assert!(std::mem::offset_of!(CallMessage, verifier) == 72);
    assert!(size_of::<CookedCredential>() <= 400);
};

/// Authenticate the asserted AUTH_NONE/AUTH_SYS identity without host RPC.
/// AUTH_SYS provides no cryptographic authentication. Unsupported flavors are
/// rejected rather than reported as authenticated.
///
/// # Safety
/// Non-null rqst/msg must point to live, aligned glibc LP64 svc_req/rpc_msg
/// objects. rq_xprt must be writable. For AUTH_SYS, rq_clntcred must provide
/// aligned writable storage of at least 400 bytes, valid through dispatch.
/// Credential/verifier buffers must remain alive while used by the request.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _authenticate(rqst: *mut c_void, msg: *mut c_void) -> c_int {
    if rqst.is_null() || msg.is_null() {
        return 7; // AUTH_FAILED: invalid local API arguments
    }
    let msg = msg.cast::<CallMessage>();
    // SAFETY: the caller supplies the documented LP64 objects; only initialized
    // auth descriptors are read, not padding or unused rpc_msg union members.
    let (request, credential, verifier) = unsafe {
        (
            &mut *rqst.cast::<ServiceRequest>(),
            ptr::read(ptr::addr_of!((*msg).credential)),
            ptr::read(ptr::addr_of!((*msg).verifier)),
        )
    };
    // SAFETY: the public API requires the request's transport/cooked storage
    // and descriptor buffers to remain valid through this operation.
    unsafe { authenticate_request(request, credential, verifier) }
}

unsafe fn authenticate_request(
    request: &mut ServiceRequest,
    credential: OpaqueAuth,
    verifier: OpaqueAuth,
) -> c_int {
    request.credential = credential;
    if request.transport.is_null() {
        return 7;
    }
    // SAFETY: the API caller owns the writable transport. Reset the outgoing
    // verifier for every call while retaining its preallocated storage pointer.
    let outgoing = unsafe { &mut (*request.transport).verifier };
    outgoing.oa_flavor = 0;
    outgoing.oa_length = 0;
    match request.credential.oa_flavor {
        0 => 0,
        1 => {
            let length = request.credential.oa_length as usize;
            let mut bytes = [0u8; 400];
            if length > bytes.len() || request.credential.oa_base.is_null() {
                return 1; // AUTH_BADCRED
            }
            // SAFETY: the destination is an owned bounded byte array. The
            // shared fault-checked copier imports only the declared credential.
            if unsafe {
                crate::io_abi::iov_snapshot::copy_user_bytes(
                    request.credential.oa_base.cast(),
                    bytes.as_mut_ptr(),
                    length,
                )
            }
            .is_err()
            {
                return 1;
            }
            let policy = if frankenlibc_membrane::config::safety_level().heals_enabled() {
                service::SystemCredentialPolicy::ExactIdentity
            } else {
                service::SystemCredentialPolicy::Glibc
            };
            let Ok(sys) = service::decode_system_credential(&bytes[..length], policy) else {
                return 1;
            };
            if request.cooked.is_null() {
                return 7;
            }
            if verifier.oa_length > 400 || (verifier.oa_length != 0 && verifier.oa_base.is_null()) {
                return 3; // AUTH_BADVERF
            }
            let destination = request.cooked.cast::<CookedCredential>();
            // SAFETY: the caller provides the documented aligned cooked area.
            // All fields are initialized, and both pointers target that area.
            unsafe {
                destination.write(zeroed());
                let cooked = &mut *destination;
                cooked.machine[..sys.machine.len()].copy_from_slice(sys.machine);
                cooked.groups = sys.groups;
                cooked.params.aup_time = sys.stamp as u64;
                cooked.params.aup_machname = cooked.machine.as_mut_ptr().cast();
                cooked.params.aup_uid = sys.uid;
                cooked.params.aup_gid = sys.gid;
                cooked.params.aup_len = sys.group_count as u32;
                cooked.params.aup_gids = cooked.groups.as_mut_ptr();
            }
            if verifier.oa_length != 0 {
                *outgoing = verifier;
            }
            0
        }
        _ => 2, // AUTH_REJECTEDCRED, including unsupported AUTH_SHORT/DES
    }
}

struct Io {
    input: Vec<u8>,
    output: Vec<u8>,
    call: Option<Call>,
    cursor: usize,
    peer: libc::sockaddr_in,
    cache: Option<ReplyCache>,
}
struct Transport {
    public: UnsafeCell<SvcXprt>,
    io: UnsafeCell<Io>,
    fd: c_int,
    operation: AtomicBool,
    dispatching: AtomicBool,
    destroyed: AtomicBool,
    close_fd: AtomicBool,
}
// SAFETY: registry owns stable addresses; operation gates serialize all buffer
// access, and dispatching prevents a second receiver during a user dispatch.
// Direct concurrent C mutation of SVCXPRT fields remains outside the API contract.
unsafe impl Send for Transport {}
unsafe impl Sync for Transport {}
impl Drop for Transport {
    fn drop(&mut self) {
        if self.close_fd.load(Ordering::Relaxed) {
            let _ = raw::sys_close(self.fd);
        }
    }
}

#[derive(Clone, Copy)]
struct Registration {
    program: u32,
    version: u32,
    dispatch: Dispatch,
    published: bool,
}
struct Registry {
    transports: Vec<Arc<Transport>>,
    services: Vec<Registration>,
    generation: u64,
}
static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    transports: Vec::new(),
    services: Vec::new(),
    generation: 0,
});
static EXIT_EPOCH: AtomicU64 = AtomicU64::new(0);
fn registry() -> MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|p| p.into_inner())
}
fn lookup(x: *mut SvcXprt) -> Option<Arc<Transport>> {
    registry()
        .transports
        .iter()
        .find(|t| t.public.get() == x)
        .cloned()
}
fn error(code: c_int) -> c_int {
    unsafe { super::set_abi_errno(code) };
    0
}

struct Operation(Arc<Transport>);
impl Operation {
    fn begin(t: Arc<Transport>) -> Option<Self> {
        if t.destroyed.load(Ordering::Acquire) || t.operation.swap(true, Ordering::Acquire) {
            error(libc::EBUSY);
            None
        } else {
            Some(Self(t))
        }
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        self.0.operation.store(false, Ordering::Release);
    }
}
struct DispatchGuard(Arc<Transport>);
impl Drop for DispatchGuard {
    fn drop(&mut self) {
        self.0.dispatching.store(false, Ordering::Release);
    }
}

const EMPTY_POLL: libc::pollfd = libc::pollfd {
    fd: -1,
    events: libc::POLLIN,
    revents: 0,
};
struct PollSnapshot {
    entries: [libc::pollfd; LIMIT],
}
#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    static POLL_SNAPSHOT: UnsafeCell<PollSnapshot> = const {
        UnsafeCell::new(PollSnapshot { entries: [EMPTY_POLL; LIMIT] })
    };
}
#[cfg(feature = "owned-tls-cache")]
static POLL_SNAPSHOT: crate::owned_tls_cache::OwnedTlsCache<PollSnapshot> =
    crate::owned_tls_cache::OwnedTlsCache::new(empty_snapshot);
#[cfg(feature = "owned-tls-cache")]
fn empty_snapshot() -> PollSnapshot {
    PollSnapshot {
        entries: [EMPTY_POLL; LIMIT],
    }
}
fn with_snapshot<R>(f: impl FnOnce(&mut PollSnapshot) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        POLL_SNAPSHOT.with(f)
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        POLL_SNAPSHOT.with(|s| f(unsafe { &mut *s.get() }))
    }
}

/// Refresh existing ABI TLS slots. Their addresses stay valid, and the poll
/// backing array has thread lifetime. Never retain a lock across C access.
pub(super) fn refresh() {
    with_snapshot(|snapshot| {
        snapshot.entries.fill(EMPTY_POLL);
        let r = registry();
        let bits = super::rpc_svc_fdset_ptr().cast::<u64>();
        // SAFETY: existing accessors own aligned, initialized per-thread slots.
        unsafe { ptr::write_bytes(bits, 0, LIMIT / 64) };
        for (index, t) in r.transports.iter().enumerate() {
            snapshot.entries[index].fd = t.fd;
            unsafe { *bits.add(t.fd as usize / 64) |= 1u64 << (t.fd as usize % 64) };
        }
        unsafe {
            super::rpc_svc_max_pollfd_ptr()
                .cast::<c_int>()
                .write(r.transports.len() as c_int);
            super::rpc_svc_pollfd_ptr()
                .cast::<*mut libc::pollfd>()
                .write(snapshot.entries.as_mut_ptr());
        }
    });
}

fn buffer(length: usize) -> Result<Vec<u8>, c_int> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| libc::ENOMEM)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

pub(super) unsafe fn create(sock: c_int, sendsz: c_uint, recvsz: c_uint) -> *mut c_void {
    let size = (sendsz as usize).max(recvsz as usize);
    let size = if size == 0 {
        DEFAULT_BUFFER
    } else {
        size.max(64)
    };
    if size > MAX_BUFFER {
        error(libc::EINVAL);
        return ptr::null_mut();
    }
    let created = sock == -1;
    let fd = if created {
        match raw::sys_socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
            Ok(fd) => fd,
            Err(e) => {
                error(e);
                return ptr::null_mut();
            }
        }
    } else {
        sock
    };
    let build = (|| -> Result<Arc<Transport>, c_int> {
        if fd < 0 {
            return Err(libc::EBADF);
        }
        if fd >= LIMIT as c_int {
            return Err(libc::EMFILE);
        }
        if registry().transports.iter().any(|t| t.fd == fd) {
            return Err(libc::EBUSY);
        }
        let mut kind = 0i32;
        let mut length = size_of::<c_int>() as u32;
        unsafe {
            raw::sys_getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut c_int).cast(),
                &mut length,
            )
        }?;
        if kind != libc::SOCK_DGRAM {
            return Err(libc::EPROTOTYPE);
        }
        let mut address: libc::sockaddr_in = unsafe { zeroed() };
        let mut length = size_of::<libc::sockaddr_in>() as u32;
        unsafe {
            raw::sys_getsockname(
                fd,
                (&mut address as *mut libc::sockaddr_in).cast(),
                &mut length,
            )
        }?;
        if address.sin_family as c_int != libc::AF_INET {
            return Err(libc::EAFNOSUPPORT);
        }
        if address.sin_port == 0 {
            unsafe { raw::sys_bind(fd, (&address as *const libc::sockaddr_in).cast(), length) }?;
            unsafe {
                raw::sys_getsockname(
                    fd,
                    (&mut address as *mut libc::sockaddr_in).cast(),
                    &mut length,
                )
            }?;
        }
        let input = buffer(size)?;
        let output = buffer(size)?;
        let public = SvcXprt {
            sock: fd,
            port: u16::from_be(address.sin_port),
            ops: &OPS,
            addrlen: 0,
            raddr: unsafe { zeroed() },
            verifier: OpaqueAuth {
                oa_flavor: 0,
                oa_base: ptr::null_mut(),
                oa_length: 0,
            },
            private1: ptr::null_mut(),
            private2: ptr::null_mut(),
            padding: [0; 256],
        };
        Ok(Arc::new(Transport {
            public: UnsafeCell::new(public),
            fd,
            io: UnsafeCell::new(Io {
                input,
                output,
                call: None,
                cursor: 0,
                peer: unsafe { zeroed() },
                cache: None,
            }),
            operation: AtomicBool::new(false),
            dispatching: AtomicBool::new(false),
            destroyed: AtomicBool::new(false),
            close_fd: AtomicBool::new(created),
        }))
    })();
    match build {
        Err(e) => {
            if created {
                let _ = raw::sys_close(fd);
            }
            error(e);
            ptr::null_mut()
        }
        Ok(t) => {
            let mut r = registry();
            if r.transports.iter().any(|other| other.fd == fd)
                || r.transports.try_reserve(1).is_err()
            {
                drop(r);
                error(libc::EBUSY);
                return ptr::null_mut();
            }
            // A successful SVC transport owns its descriptor, even if supplied
            // by the caller. Failed creation must leave a supplied fd open.
            t.close_fd.store(true, Ordering::Relaxed);
            let x = t.public.get();
            r.transports.push(t);
            drop(r);
            refresh();
            x.cast()
        }
    }
}

unsafe extern "C" fn destroy(x: *mut SvcXprt) {
    let t = {
        let mut r = registry();
        let Some(index) = r.transports.iter().position(|t| t.public.get() == x) else {
            return;
        };
        r.transports[index].destroyed.store(true, Ordering::Release);
        r.transports.remove(index)
    };
    drop(t);
    refresh();
}

enum Receive {
    Call,
    Replayed,
    Unavailable,
}

// Caller holds the operation gate. All input/output buffers are owned and
// bounded. MSG_TRUNC detects oversize UDP packets rather than dispatching a prefix.
fn receive(t: &Transport) -> Receive {
    // SAFETY: the caller's Operation owns exclusive access to transport buffers.
    let io = unsafe { &mut *t.io.get() };
    io.call = None;
    let mut peer: libc::sockaddr_in = unsafe { zeroed() };
    let mut length = size_of::<libc::sockaddr_in>() as u32;
    let count = unsafe {
        raw::sys_recvfrom(
            t.fd,
            io.input.as_mut_ptr(),
            io.input.len(),
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            (&mut peer as *mut libc::sockaddr_in).cast(),
            &mut length,
        )
    };
    let count = match count {
        Ok(n) => n as usize,
        Err(e) => {
            error(e);
            return Receive::Unavailable;
        }
    };
    if count > io.input.len()
        || length as usize != size_of::<libc::sockaddr_in>()
        || peer.sin_family as c_int != libc::AF_INET
    {
        error(libc::EMSGSIZE);
        return Receive::Unavailable;
    }
    io.peer = peer;
    unsafe {
        (*t.public.get()).raddr = peer;
        (*t.public.get()).addrlen = length as c_int;
    }
    // Registration mutations and this snapshot use the same registry lock.
    // A call racing registration may finish against its earlier snapshot;
    // subsequent generation snapshots cannot hit that old cache entry.
    // Keep the default no-cache path free of an extra registry acquisition.
    let generation = if io.cache.is_some() {
        registry().generation
    } else {
        0
    };
    let identity = Peer {
        address: peer.sin_addr.s_addr,
        port: peer.sin_port,
    };
    if let Some(reply) = io
        .cache
        .as_ref()
        .and_then(|cache| cache.lookup(identity, generation, &io.input[..count]))
    {
        // SAFETY: Operation retains the transport, peer and owned cache bytes
        // throughout this synchronous syscall. A replay never enters C code.
        match unsafe {
            raw::sys_sendto(
                t.fd,
                reply.as_ptr(),
                reply.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                (&peer as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>(),
            )
        } {
            Ok(n) if n as usize == reply.len() => {}
            Ok(_) => {
                error(libc::EIO);
            }
            Err(e) => {
                error(e);
            }
        }
        // Even if sending fails, this already-completed request must not
        // execute the application's side effects again in this readiness turn.
        return Receive::Replayed;
    }
    match service::decode_call(&io.input[..count]) {
        Ok(call) => {
            if let Some(cache) = &mut io.cache {
                // Own identity before an XDR decoder may mutate input bytes.
                cache.stage(identity, generation, &io.input[..count]);
            }
            io.cursor = call.arguments.start;
            io.call = Some(call);
            Receive::Call
        }
        Err(CallError::RpcVersion { xid }) => {
            if let Ok(n) = service::encode_reply_prefix(
                &mut io.output,
                xid,
                0,
                &[],
                Some(RemoteError::RpcVersion { low: 2, high: 2 }),
            ) {
                let _ = unsafe {
                    raw::sys_sendto(
                        t.fd,
                        io.output.as_ptr(),
                        n,
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        (&peer as *const libc::sockaddr_in).cast(),
                        length as usize,
                    )
                };
            }
            Receive::Unavailable
        }
        Err(_) => Receive::Unavailable,
    }
}

unsafe extern "C-unwind" fn recv(x: *mut SvcXprt, message: *mut c_void) -> c_int {
    if message.is_null() {
        return error(libc::EINVAL);
    }
    let Some(t) = lookup(x) else {
        return error(libc::EINVAL);
    };
    if t.dispatching.load(Ordering::Acquire) {
        return error(libc::EBUSY);
    }
    let Some(gate) = Operation::begin(t) else {
        return 0;
    };
    if !matches!(receive(&gate.0), Receive::Call) {
        return 0;
    }
    let io = unsafe { &mut *gate.0.io.get() };
    let length = io.call.as_ref().unwrap().arguments.end;
    let mut xdr: Xdr = unsafe { zeroed() };
    unsafe {
        super::xdrmem_create(
            (&mut xdr as *mut Xdr).cast(),
            io.input.as_mut_ptr().cast(),
            length as u32,
            super::XDR_DECODE,
        )
    };
    // Native xdr_callmsg respects caller-provided credential buffers and allocates
    // with the native XDR allocator when the public message uses null pointers.
    unsafe { super::xdr_callmsg((&mut xdr as *mut Xdr).cast(), message) }
}

unsafe extern "C" fn stat(x: *mut SvcXprt) -> c_int {
    let Some(t) = lookup(x) else {
        return 0;
    }; // XPRT_DIED
    let mut fd = libc::pollfd {
        fd: t.fd,
        events: libc::POLLIN,
        revents: 0,
    };
    match unsafe { raw::sys_poll((&mut fd as *mut libc::pollfd).cast(), 1, 0) } {
        Ok(_) if fd.revents & libc::POLLIN != 0 => 1, // XPRT_MOREREQS
        Ok(_) if fd.revents & (libc::POLLNVAL | libc::POLLERR) == 0 => 2,
        _ => 0,
    }
}

unsafe extern "C-unwind" fn getargs(
    x: *mut SvcXprt,
    proc: *mut c_void,
    object: *mut c_void,
) -> c_int {
    let Some(t) = lookup(x) else {
        return error(libc::EINVAL);
    };
    let Some(gate) = Operation::begin(t) else {
        return 0;
    };
    if proc.is_null() {
        return error(libc::EINVAL);
    }
    let mut xdr: Xdr = unsafe { zeroed() };
    {
        let io = unsafe { &mut *gate.0.io.get() };
        let Some(call) = &io.call else {
            return 0;
        };
        let remaining = call.arguments.end - io.cursor;
        unsafe {
            super::xdrmem_create(
                (&mut xdr as *mut Xdr).cast(),
                io.input.as_mut_ptr().add(io.cursor).cast(),
                remaining as u32,
                super::XDR_DECODE,
            )
        };
    }
    let function: Procedure = unsafe { std::mem::transmute(proc) };
    let result = unsafe { function((&mut xdr as *mut Xdr).cast(), object) };
    let consumed = unsafe { ((*xdr.x_ops).x_getpostn)(&xdr) } as usize;
    unsafe {
        (*gate.0.io.get()).cursor += consumed;
    }
    result
}

unsafe extern "C-unwind" fn freeargs(
    x: *mut SvcXprt,
    proc: *mut c_void,
    object: *mut c_void,
) -> c_int {
    let Some(t) = lookup(x) else {
        return error(libc::EINVAL);
    };
    let Some(_gate) = Operation::begin(t) else {
        return 0;
    };
    if proc.is_null() {
        return error(libc::EINVAL);
    }
    let mut xdr: Xdr = unsafe { zeroed() };
    xdr.x_op = super::XDR_FREE;
    let function: Procedure = unsafe { std::mem::transmute(proc) };
    unsafe { function((&mut xdr as *mut Xdr).cast(), object) }
}

unsafe fn send(
    x: *mut SvcXprt,
    failure: Option<RemoteError>,
    proc: *mut c_void,
    object: *mut c_void,
    verifier: Option<OpaqueAuth>,
) -> c_int {
    let Some(t) = lookup(x) else {
        return error(libc::EINVAL);
    };
    let Some(gate) = Operation::begin(t) else {
        return 0;
    };
    let mut xdr: Xdr = unsafe { zeroed() };
    let (prefix, peer) = {
        let io = unsafe { &mut *gate.0.io.get() };
        let Some(call) = &io.call else {
            return 0;
        };
        let v = verifier.unwrap_or_else(|| unsafe { ptr::read(&(*x).verifier) });
        let mut bytes = [0u8; 400];
        if v.oa_length as usize > bytes.len() || (v.oa_length != 0 && v.oa_base.is_null()) {
            return error(libc::EINVAL);
        }
        if v.oa_length != 0 {
            // Public verifier storage remains the caller's responsibility.
            unsafe {
                ptr::copy_nonoverlapping(
                    v.oa_base.cast::<u8>(),
                    bytes.as_mut_ptr(),
                    v.oa_length as usize,
                )
            };
        }
        let prefix = match service::encode_reply_prefix(
            &mut io.output,
            call.xid,
            v.oa_flavor as u32,
            &bytes[..v.oa_length as usize],
            failure,
        ) {
            Ok(n) => n,
            Err(_) => return error(libc::EMSGSIZE),
        };
        unsafe {
            super::xdrmem_create(
                (&mut xdr as *mut Xdr).cast(),
                io.output.as_mut_ptr().add(prefix).cast(),
                (io.output.len() - prefix) as u32,
                super::XDR_ENCODE,
            )
        };
        (prefix, io.peer)
    };
    // The public initializer may decline a policy decision without an error
    // return. Do not pass that zeroed stream to an application encoder.
    if xdr.x_ops.is_null() {
        return error(libc::EINVAL);
    }
    if failure.is_none() && !proc.is_null() {
        let function: Procedure = unsafe { std::mem::transmute(proc) };
        if unsafe { function((&mut xdr as *mut Xdr).cast(), object) } == 0 {
            return 0;
        }
    }
    if gate.0.destroyed.load(Ordering::Acquire) {
        return 0;
    }
    // SAFETY: the encoder has returned and Operation still exclusively owns
    // these buffers; no Rust reference was retained across the C callback.
    let io = unsafe { &mut *gate.0.io.get() };
    // An application encoder can modify the public XDR cursor. Check its
    // position against the owned output before sending or slicing cache bytes;
    // do not dispatch through a potentially modified operation table.
    let Some(length) = (xdr.x_private as usize)
        .checked_sub(io.output.as_ptr() as usize)
        .filter(|&length| length >= prefix && length <= io.output.len())
    else {
        return error(libc::EMSGSIZE);
    };
    match unsafe {
        raw::sys_sendto(
            gate.0.fd,
            io.output.as_ptr(),
            length,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            (&peer as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>(),
        )
    } {
        Ok(n) if n as usize == length => {
            if let Some(cache) = &mut io.cache {
                cache.remember_staged(&io.output[..length]);
            }
            1
        }
        Ok(_) => error(libc::EIO),
        Err(e) => error(e),
    }
}

unsafe extern "C-unwind" fn reply(x: *mut SvcXprt, message: *mut c_void) -> c_int {
    if message.is_null() {
        return error(libc::EINVAL);
    }
    // glibc LP64 rpc_msg: direction at 8; reply discriminant at 16; body at 24.
    let b = message.cast::<u8>();
    if unsafe { b.add(8).cast::<c_int>().read() } != 1 {
        return 0;
    }
    match unsafe { b.add(16).cast::<c_int>().read() } {
        0 => {
            let a = unsafe { &*b.add(24).cast::<AcceptedReply>() };
            let failure = match a.ar_stat {
                0 => None,
                1 => Some(RemoteError::ProgramUnavailable),
                2 => Some(RemoteError::ProgramVersion {
                    low: a.ar_u1 as u32,
                    high: a.ar_u2 as u32,
                }),
                3 => Some(RemoteError::ProcedureUnavailable),
                4 => Some(RemoteError::GarbageArguments),
                5 => Some(RemoteError::System),
                _ => return 0,
            };
            unsafe {
                send(
                    x,
                    failure,
                    a.ar_u2 as *mut c_void,
                    a.ar_u1 as *mut c_void,
                    Some(ptr::read(&a.ar_verf)),
                )
            }
        }
        1 => {
            let r = unsafe { &*b.add(24).cast::<RejectedReply>() };
            let failure = match r.rj_stat {
                0 => RemoteError::RpcVersion {
                    low: r.rj_u1 as u32,
                    high: r.rj_u2 as u32,
                },
                1 => RemoteError::Authentication(r.rj_u1 as u32),
                _ => return 0,
            };
            unsafe { send(x, Some(failure), ptr::null_mut(), ptr::null_mut(), None) }
        }
        _ => 0,
    }
}
static OPS: SvcOps = SvcOps {
    recv,
    stat,
    getargs,
    reply,
    freeargs,
    destroy,
};

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn svcudp_create(sock: c_int) -> *mut c_void {
    unsafe { create(sock, 0, 0) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn svcudp_bufcreate(
    sock: c_int,
    sendsz: c_uint,
    recvsz: c_uint,
) -> *mut c_void {
    unsafe { create(sock, sendsz, recvsz) }
}

/// Enable bounded duplicate-reply caching on a native UDP transport.
/// Repeated enablement leaves the existing cache intact. All storage is
/// reserved here, outside application callbacks and service packet handling.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn svcudp_enablecache(x: *mut c_void, count: u64) -> c_int {
    let Some(t) = lookup(x.cast()) else {
        return error(libc::EINVAL);
    };
    let Some(gate) = Operation::begin(t) else {
        return 0;
    };
    if gate.0.dispatching.load(Ordering::Acquire) {
        return error(libc::EBUSY);
    }
    // SAFETY: Operation excludes receive/reply and other cache configuration.
    let io = unsafe { &mut *gate.0.io.get() };
    if io.cache.is_some() {
        return error(libc::EINVAL);
    }
    let Ok(count) = usize::try_from(count) else {
        return error(libc::ENOMEM);
    };
    match ReplyCache::new(count, io.input.len().max(io.output.len())) {
        Ok(cache) => {
            io.cache = Some(cache);
            1
        }
        Err(CacheError::InvalidSize) => error(libc::EINVAL),
        Err(CacheError::NoMemory) => error(libc::ENOMEM),
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn svc_sendreply(
    x: *mut c_void,
    proc: *mut c_void,
    object: *mut c_void,
) -> c_int {
    unsafe { send(x.cast(), None, proc, object, None) }
}

macro_rules! failure_export {
    ($name:ident, $failure:expr) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(x: *mut c_void) {
            unsafe {
                send(
                    x.cast(),
                    Some($failure),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    None,
                )
            };
        }
    };
}
failure_export!(svcerr_decode, RemoteError::GarbageArguments);
failure_export!(svcerr_noproc, RemoteError::ProcedureUnavailable);
failure_export!(svcerr_noprog, RemoteError::ProgramUnavailable);
failure_export!(svcerr_systemerr, RemoteError::System);
failure_export!(svcerr_weakauth, RemoteError::Authentication(5));
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_auth(x: *mut c_void, why: c_int) {
    unsafe {
        send(
            x.cast(),
            Some(RemoteError::Authentication(why as u32)),
            ptr::null_mut(),
            ptr::null_mut(),
            None,
        )
    };
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_progvers(x: *mut c_void, low: u64, high: u64) {
    unsafe {
        send(
            x.cast(),
            Some(RemoteError::ProgramVersion {
                low: low as u32,
                high: high as u32,
            }),
            ptr::null_mut(),
            ptr::null_mut(),
            None,
        )
    };
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn svc_register(
    x: *mut c_void,
    program: u64,
    version: u64,
    dispatch: *mut c_void,
    protocol: c_int,
) -> c_int {
    let Some(t) = lookup(x.cast()) else {
        return error(libc::EINVAL);
    };
    if program > u32::MAX as u64 || version > u32::MAX as u64 || dispatch.is_null() {
        return error(libc::EINVAL);
    }
    if protocol != 0 && protocol != libc::IPPROTO_UDP {
        return error(libc::EPROTONOSUPPORT);
    }
    let mut r = registry();
    if let Some(s) = r
        .services
        .iter()
        .find(|s| s.program == program as u32 && s.version == version as u32)
    {
        if s.dispatch as *mut c_void != dispatch {
            return 0;
        }
    } else if r.services.try_reserve(1).is_err() {
        return error(libc::ENOMEM);
    }
    drop(r);
    if protocol != 0
        && unsafe { super::pmap_set(program, version, protocol, (*t.public.get()).port) } == 0
    {
        return 0;
    }
    let mut r = registry();
    if let Some(s) = r
        .services
        .iter_mut()
        .find(|s| s.program == program as u32 && s.version == version as u32)
    {
        if s.dispatch as *mut c_void != dispatch {
            return 0;
        }
        s.published |= protocol != 0;
    } else {
        if r.services.try_reserve(1).is_err() {
            return error(libc::ENOMEM);
        }
        r.services.push(Registration {
            program: program as u32,
            version: version as u32,
            dispatch: unsafe {
                std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C-unwind" fn(*mut ServiceRequest, *mut SvcXprt),
                >(dispatch)
            },
            published: protocol != 0,
        });
    }
    // Conservatively retire cached responses after every successful service
    // registration, including a repeated registration by the same callback.
    r.generation = r.generation.wrapping_add(1);
    1
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn svc_unregister(program: u64, version: u64) {
    let published = {
        let mut r = registry();
        let published = r
            .services
            .iter()
            .any(|s| s.program as u64 == program && s.version as u64 == version && s.published);
        let previous_len = r.services.len();
        r.services
            .retain(|s| s.program as u64 != program || s.version as u64 != version);
        if r.services.len() != previous_len {
            r.generation = r.generation.wrapping_add(1);
        }
        published
    };
    if published {
        unsafe { super::pmap_unset(program, version) };
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn svc_getreq_common(fd: c_int) {
    let t = registry().transports.iter().find(|t| t.fd == fd).cloned();
    let Some(t) = t else {
        return;
    };
    if t.dispatching.swap(true, Ordering::Acquire) {
        return;
    }
    let dispatch_guard = DispatchGuard(t);
    let t = &dispatch_guard.0;
    // Bound one readiness turn so a perpetually busy socket cannot starve peers.
    for _ in 0..32 {
        if t.destroyed.load(Ordering::Acquire) {
            break;
        }
        let Some(op) = Operation::begin(Arc::clone(t)) else {
            break;
        };
        match receive(t) {
            Receive::Call => {}
            Receive::Replayed => continue,
            Receive::Unavailable => break,
        }
        let x = t.public.get();
        // SAFETY: every field in the cooked ABI layout admits the zero value.
        // This area stays in place until the callback finishes or unwinds.
        let mut cooked: CookedCredential = unsafe { zeroed() };
        let (mut request, auth_error) = {
            // SAFETY: the operation gate owns the transport input buffer, and
            // the dispatch guard retains it until the callback returns.
            let io = unsafe { &*t.io.get() };
            let call = io.call.as_ref().unwrap();
            let credential = &io.input[call.credential.body.clone()];
            let mut request = ServiceRequest {
                program: call.program as u64,
                version: call.version as u64,
                procedure: call.procedure as u64,
                credential: OpaqueAuth {
                    oa_flavor: 0,
                    oa_base: ptr::null_mut(),
                    oa_length: 0,
                },
                cooked: (&mut cooked as *mut CookedCredential).cast(),
                transport: x,
            };
            let credential = OpaqueAuth {
                oa_flavor: call.credential.flavor as c_int,
                oa_base: credential.as_ptr().cast_mut().cast(),
                oa_length: credential.len() as u32,
            };
            let verifier = &io.input[call.verifier.body.clone()];
            let verifier = OpaqueAuth {
                oa_flavor: call.verifier.flavor as c_int,
                oa_base: verifier.as_ptr().cast_mut().cast(),
                oa_length: verifier.len() as u32,
            };
            // SAFETY: decoded ranges are bounded by the retained input, the
            // operation gate owns x, and cooked remains alive through dispatch.
            let status = unsafe { authenticate_request(&mut request, credential, verifier) };
            (request, status)
        };
        drop(op);
        if auth_error != 0 {
            // SAFETY: the dispatch guard retains this live transport.
            unsafe { svcerr_auth(x.cast(), auth_error) };
            continue;
        }
        let (handler, range) = {
            let r = registry();
            let handler = r
                .services
                .iter()
                .find(|s| {
                    s.program as u64 == request.program && s.version as u64 == request.version
                })
                .map(|s| s.dispatch);
            let mut range: Option<(u32, u32)> = None;
            for s in &r.services {
                if s.program as u64 == request.program {
                    range = Some(range.map_or((s.version, s.version), |(low, high)| {
                        (low.min(s.version), high.max(s.version))
                    }));
                }
            }
            (handler, range)
        };
        if let Some(handler) = handler {
            unsafe { handler(&mut request, x) };
        } else if let Some((low, high)) = range {
            unsafe { svcerr_progvers(x.cast(), low as u64, high as u64) };
        } else {
            unsafe { svcerr_noprog(x.cast()) };
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn svc_getreqset(readfds: *mut c_void) {
    if readfds.is_null() {
        return;
    }
    // Snapshot before callbacks, which can alter the caller's event set.
    let bits = unsafe { readfds.cast::<[u64; LIMIT / 64]>().read() };
    for fd in 0..LIMIT {
        if bits[fd / 64] & (1u64 << (fd % 64)) != 0 {
            unsafe { svc_getreq_common(fd as c_int) };
        }
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn svc_getreq(mask: c_int) {
    for fd in 0..32 {
        if mask as u32 & (1u32 << fd) != 0 {
            unsafe { svc_getreq_common(fd) };
        }
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn svc_getreq_poll(fds: *mut c_void, ready: c_int) {
    if fds.is_null() || ready <= 0 {
        return;
    }
    // The second argument is poll's return value, NOT array length. Snapshot
    // the registered poll-array extent before dispatch can change registration.
    let count = unsafe { *super::rpc_svc_max_pollfd_ptr().cast::<c_int>() }.max(0) as usize;
    let mut selected = [-1; LIMIT];
    let mut remaining = ready;
    for (index, slot) in selected.iter_mut().enumerate().take(count.min(LIMIT)) {
        let p = unsafe { fds.cast::<libc::pollfd>().add(index).read() };
        if p.revents != 0 {
            remaining -= 1;
            if p.revents & libc::POLLIN != 0 {
                *slot = p.fd;
            }
        }
        if remaining == 0 {
            break;
        }
    }
    for fd in selected {
        if fd >= 0 {
            unsafe { svc_getreq_common(fd) };
        }
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn svc_exit() {
    EXIT_EPOCH.fetch_add(1, Ordering::Release);
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn svc_run() {
    let epoch = EXIT_EPOCH.load(Ordering::Acquire);
    loop {
        if EXIT_EPOCH.load(Ordering::Acquire) != epoch {
            return;
        }
        let mut fds = [EMPTY_POLL; LIMIT];
        let count = {
            let r = registry();
            for (p, t) in fds.iter_mut().zip(&r.transports) {
                p.fd = t.fd;
            }
            r.transports.len()
        };
        if count == 0 {
            return;
        }
        // A finite readiness wait also observes svc_exit from another thread
        // without allocating a process-global wake descriptor.
        let polled = unsafe {
            crate::pthread_abi::at_cancellation_point(|| {
                raw::sys_poll(fds.as_mut_ptr().cast(), count, 100)
            })
        };
        match polled {
            Err(libc::EINTR) | Ok(0) => continue,
            Err(_) => return,
            _ => {}
        }
        for p in &fds[..count] {
            if p.revents & libc::POLLIN != 0 {
                unsafe { svc_getreq_common(p.fd) };
            }
        }
    }
}
