//! Native portmapper DUMP, CALLIT and broadcast clients.
//!
//! Both operations reuse the native CLIENT transport, callbacks and deadline
//! machinery. No rpcbind daemon is embedded and no host RPC function is called.
//! DUMP uses TCP; CALLIT uses UDP and preserves GNU's callback-visible port
//! publication and caller-address reset behavior.

use super::super::{Pmap, PmapList, XDR_DECODE, XDR_ENCODE, XDR_FREE, XDR_TRUE};
use super::{
    Auth, Client, CreateFailure, MAX_STREAM_BUFFER, Network, RPC_SYSTEMERROR, Reply, RpcError,
    Socket, Timeval, Xdr, XdrProc, buffer, call, creation_error, destroy, import, make_client,
    monotonic, nanos, publish, transaction_id, wire,
};
use frankenlibc_core::rpc::wire::portmap::{MappingError, decode_mappings};
use frankenlibc_core::syscall as raw;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};
use std::ffi::{c_int, c_uint, c_void};
use std::mem::size_of;
use std::ptr;

const PORTMAPPER: u64 = 100000;
const VERSION: u64 = 2;
const MAX_MAPPINGS: usize = 65536;

type Codec = unsafe extern "C-unwind" fn(*mut c_void, *mut c_void) -> c_int;

struct OwnedClient(*mut Client);
impl Drop for OwnedClient {
    fn drop(&mut self) {
        // SAFETY: this guard owns a freshly constructed CLIENT. The operation
        // gate unwinds before this guard, including on application exceptions.
        unsafe { destroy(self.0) };
    }
}

struct ResetPort(*mut u16);
impl Drop for ResetPort {
    fn drop(&mut self) {
        // SAFETY: the address remains caller-owned throughout the call. The
        // shared copier checks tracked extents and faults on every publication.
        let _ = unsafe { publish(&0u16, self.0) };
    }
}

unsafe fn endpoint(address: *mut c_void) -> Result<(libc::sockaddr_in, ResetPort), RpcError> {
    // SAFETY: import validates the complete public address before field access.
    let mut peer = unsafe { import::<libc::sockaddr_in>(address.cast()) }?;
    if peer.sin_family as c_int != libc::AF_INET {
        return Err(RpcError::system(RPC_SYSTEMERROR, libc::EAFNOSUPPORT));
    }
    let slot = (address as usize)
        .checked_add(std::mem::offset_of!(libc::sockaddr_in, sin_port))
        .ok_or_else(|| RpcError::system(RPC_SYSTEMERROR, libc::EFAULT))? as *mut u16;
    peer.sin_port = 111u16.to_be();
    // GNU codecs observe port 111 during the operation, followed by zero on
    // return even when encoding, decoding, transport or creation fails.
    // SAFETY: publish uses the same fault-checked copier as the native client.
    unsafe { publish(&peer.sin_port, slot) }?;
    Ok((peer, ResetPort(slot)))
}

unsafe fn client(
    peer: &mut libc::sockaddr_in,
    network: Network,
    receive: c_uint,
) -> Result<OwnedClient, CreateFailure> {
    let mut descriptor = -1;
    // SAFETY: constructor inputs are owned initialized stack objects. A nonzero
    // port prevents recursive mapper discovery, and the new socket is owned.
    let pointer = unsafe {
        make_client(
            (peer as *mut libc::sockaddr_in).cast(),
            PORTMAPPER,
            VERSION,
            Timeval {
                tv_sec: 3,
                tv_usec: 0,
            },
            &mut descriptor,
            0,
            receive,
            network,
        )
    }?;
    Ok(OwnedClient(pointer.cast()))
}

struct OwnedMappings(*mut PmapList);
impl Drop for OwnedMappings {
    fn drop(&mut self) {
        while !self.0.is_null() {
            // SAFETY: only this guard owns the fully initialized private list.
            // The next pointer is copied before releasing the current node.
            unsafe {
                let node = self.0;
                self.0 = (*node).pml_next;
                crate::malloc_abi::free(node.cast());
            }
        }
    }
}

unsafe extern "C" fn no_arguments(_: *mut c_void, _: *mut c_void) -> c_int {
    XDR_TRUE
}

unsafe extern "C" fn mapping_results(stream: *mut c_void, destination: *mut c_void) -> c_int {
    // SAFETY: only our native call() invokes this private callback, with a
    // live bounded memory XDR and the OwnedMappings stack object below.
    let stream = unsafe { &*stream.cast::<Xdr>() };
    if stream.x_op != XDR_DECODE || stream.x_ops.is_null() {
        return 0;
    }
    // SAFETY: native invocation builds this memory stream from the exact
    // received result range, never the receive allocation's unused capacity.
    let bytes = unsafe {
        std::slice::from_raw_parts(stream.x_private.cast::<u8>(), stream.x_handy as usize)
    };
    let mappings = match decode_mappings(bytes, MAX_MAPPINGS) {
        Ok(mappings) => mappings,
        Err(error) => {
            if error == MappingError::Allocation {
                // SAFETY: this updates only the calling thread's errno.
                unsafe { super::super::set_abi_errno(libc::ENOMEM) };
            }
            return 0;
        }
    };
    let mut list = OwnedMappings(ptr::null_mut());
    let mut tail: *mut PmapList = ptr::null_mut();
    for mapping in mappings {
        // SAFETY: the native allocator returns suitable alignment for PmapList.
        let node = unsafe { crate::malloc_abi::malloc(size_of::<PmapList>()) }.cast::<PmapList>();
        if node.is_null() {
            return 0;
        }
        // SAFETY: node is private writable storage. All fields are initialized
        // before linking it; failed allocation drops every preceding node.
        unsafe {
            node.write(PmapList {
                pml_map: Pmap {
                    pm_prog: mapping.program as u64,
                    pm_vers: mapping.version as u64,
                    pm_prot: mapping.protocol as u64,
                    pm_port: mapping.port as u64,
                },
                pml_next: ptr::null_mut(),
            });
            if tail.is_null() {
                list.0 = node;
            } else {
                (*tail).pml_next = node;
            }
        }
        tail = node;
    }
    // SAFETY: destination is our live guard, initially empty; replacing it
    // transfers all nodes together only after complete decoding/allocation.
    unsafe { *destination.cast::<OwnedMappings>() = list };
    XDR_TRUE
}

pub(crate) unsafe fn getmaps(address: *mut c_void) -> *mut c_void {
    let (_, decision) = super::super::runtime_policy::decide(
        ApiFamily::Socket,
        address as usize,
        0,
        false,
        true,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        creation_error(
            RPC_SYSTEMERROR,
            RpcError::system(RPC_SYSTEMERROR, libc::EACCES),
        );
        super::super::runtime_policy::observe(ApiFamily::Socket, decision.profile, 100, true);
        return ptr::null_mut();
    }
    let result = (|| -> Result<OwnedMappings, RpcError> {
        // SAFETY: caller keeps the live public address through this call.
        let (mut peer, _reset) = unsafe { endpoint(address) }?;
        // SAFETY: this is a private copy and the client owns its descriptor.
        let client = unsafe { client(&mut peer, Network::Tcp, MAX_STREAM_BUFFER as c_uint) }
            .map_err(|failure| {
                creation_error(failure.status, failure.error);
                failure.error
            })?;
        let mut mappings = OwnedMappings(ptr::null_mut());
        // SAFETY: private callbacks receive only our live owned result guard.
        let status = unsafe {
            call(
                client.0,
                4,
                Some(no_arguments),
                ptr::null_mut(),
                Some(mapping_results),
                (&mut mappings as *mut OwnedMappings).cast(),
                Timeval {
                    tv_sec: 60,
                    tv_usec: 0,
                },
            )
        };
        if status != 0 {
            // Preserve the GNU diagnostic, but never publish a partially
            // decoded list on a malformed reply.
            // SAFETY: the client and static diagnostic prefix remain live.
            unsafe {
                super::super::clnt_perror(client.0.cast(), c"pmap_getmaps.c: rpc problem".as_ptr())
            };
            return Err(RpcError::status(status));
        }
        Ok(mappings)
    })();
    super::super::runtime_policy::observe(
        ApiFamily::Socket,
        decision.profile,
        100,
        result.is_err(),
    );
    match result {
        Ok(mut mappings) => std::mem::replace(&mut mappings.0, ptr::null_mut()).cast(),
        Err(_) => ptr::null_mut(),
    }
}

struct Arguments {
    program: u64,
    version: u64,
    procedure: u64,
    callback: Codec,
    pointer: *mut c_void,
}

unsafe extern "C-unwind" fn remote_arguments(stream: *mut c_void, opaque: *mut c_void) -> c_int {
    // SAFETY: these are the native memory stream and live private call context.
    let xdr = stream.cast::<Xdr>();
    let args = unsafe { &mut *opaque.cast::<Arguments>() };
    if unsafe { (*xdr).x_op != XDR_ENCODE || (*xdr).x_ops.is_null() } {
        return 0;
    }
    for word in [&mut args.program, &mut args.version, &mut args.procedure] {
        // SAFETY: these three u_longs are initialized owned scalars. The
        // existing encoder preserves GNU's low-32-bit wire representation.
        if unsafe { super::super::xdr_u_long(stream, word) } == 0 {
            return 0;
        }
    }
    // SAFETY: the initialized native XDR operations own the memory cursor.
    let length_position = unsafe { ((*(*xdr).x_ops).x_getpostn)(xdr) };
    let mut length = 0u64;
    if unsafe { super::super::xdr_u_long(stream, &mut length) } == 0 {
        return 0;
    }
    let begin = unsafe { ((*(*xdr).x_ops).x_getpostn)(xdr) };
    // SAFETY: the public callback/payload remain live. C-unwind permits the
    // same exception and pthread-exit cleanup contract as ordinary CLIENT calls.
    if unsafe { (args.callback)(stream, args.pointer) } == 0 {
        return 0;
    }
    let end = unsafe { ((*(*xdr).x_ops).x_getpostn)(xdr) };
    let Some(used) = end.checked_sub(begin) else {
        return 0;
    };
    length = used as u64;
    if unsafe { ((*(*xdr).x_ops).x_setpostn)(xdr, length_position) } == 0
        || unsafe { super::super::xdr_u_long(stream, &mut length) } == 0
        || unsafe { ((*(*xdr).x_ops).x_setpostn)(xdr, end) } == 0
    {
        return 0;
    }
    XDR_TRUE
}

struct Results {
    port: *mut u64,
    callback: Codec,
    pointer: *mut c_void,
}

unsafe extern "C-unwind" fn remote_results(stream: *mut c_void, opaque: *mut c_void) -> c_int {
    // SAFETY: opaque names the private live Results context for this operation.
    let results = unsafe { &mut *opaque.cast::<Results>() };
    let mut port = 0u64;
    // SAFETY: decode writes a bounded wire word into this owned u_long.
    if unsafe { super::super::xdr_u_long(stream, &mut port) } == 0 {
        return 0;
    }
    // GNU publishes port before invoking the result codec, including when
    // that codec later fails. Do not narrow this public LP64 u_long output.
    // SAFETY: publish checks both tracked bounds and actual writable memory.
    if unsafe { publish(&port, results.port) }.is_err() {
        return 0;
    }
    let mut declared_length = 0u64;
    if unsafe { super::super::xdr_u_long(stream, &mut declared_length) } == 0 {
        return 0;
    }
    // GNU exposes the remaining actual result stream to the codec even when
    // this advisory length differs. The native stream is still bounded by
    // received bytes, so no unreceived storage becomes available to a codec.
    unsafe { (results.callback)(stream, results.pointer) }
}

#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn remote_call(
    address: *mut c_void,
    program: u64,
    version: u64,
    procedure: u64,
    arguments: *mut c_void,
    argument: *mut c_void,
    results: *mut c_void,
    result: *mut c_void,
    timeout: Timeval,
    port: *mut u64,
) -> c_int {
    let (_, decision) = super::super::runtime_policy::decide(
        ApiFamily::Socket,
        address as usize,
        0,
        false,
        true,
        0,
    );
    let outcome = if matches!(decision.action, MembraneAction::Deny) {
        Err(RpcError::system(RPC_SYSTEMERROR, libc::EACCES))
    } else {
        (|| -> Result<c_int, RpcError> {
            // SAFETY: caller keeps the live public address through this call.
            let (mut peer, _reset) = unsafe { endpoint(address) }?;
            nanos(timeout, false)?;
            if arguments.is_null() {
                return Ok(1);
            }
            if results.is_null() {
                return Ok(2);
            }
            if port.is_null() {
                return Err(RpcError::system(RPC_SYSTEMERROR, libc::EFAULT));
            }
            // Admit the complete LP64 output before running application code.
            // Copying its current value back also checks write-only faults;
            // successful valid calls still publish the server's port later.
            let original = unsafe { import::<u64>(port.cast_const()) }?;
            unsafe { publish(&original, port) }?;
            // SAFETY: this is a private copy; construction owns the new socket.
            let client = unsafe { client(&mut peer, Network::Datagram, 0) }.map_err(|failure| {
                creation_error(failure.status, failure.error);
                RpcError::status(16)
            })?;
            let mut args = Arguments {
                program,
                version,
                procedure,
                // SAFETY: non-null public XDR callbacks use this C layout.
                callback: unsafe { std::mem::transmute::<*mut c_void, Codec>(arguments) },
                pointer: argument,
            };
            let mut results = Results {
                port,
                // SAFETY: non-null public XDR callbacks use this C layout.
                callback: unsafe { std::mem::transmute::<*mut c_void, Codec>(results) },
                pointer: result,
            };
            // SAFETY: native invoke explicitly calls callbacks with C-unwind.
            // XdrProc is only the public table representation of these pointers.
            let encode: XdrProc =
                unsafe { std::mem::transmute::<Codec, XdrProc>(remote_arguments) };
            let decode: XdrProc = unsafe { std::mem::transmute::<Codec, XdrProc>(remote_results) };
            Ok(unsafe {
                call(
                    client.0,
                    5,
                    Some(encode),
                    (&mut args as *mut Arguments).cast(),
                    Some(decode),
                    (&mut results as *mut Results).cast(),
                    timeout,
                )
            })
        })()
    };
    let status = outcome.unwrap_or_else(|error| error.status);
    super::super::runtime_policy::observe(ApiFamily::Socket, decision.profile, 100, status != 0);
    status
}

/// Broadcast RPC uses the historical 1400-byte UDP packet budget, including
/// the RPC and CALLIT envelopes. One encoded request is retransmitted unchanged
/// after 4, 6, 8, 10, 12 and 14 second receive intervals. Unrelated packets and
/// EINTR never reset an interval, so a noisy network cannot extend the budget.
const BROADCAST_BUFFER: usize = 1400;
type EachResult = unsafe extern "C-unwind" fn(*mut c_void, *mut libc::sockaddr_in) -> c_int;

struct BroadcastAuth(*mut Auth);
impl Drop for BroadcastAuth {
    fn drop(&mut self) {
        // SAFETY: this guard exclusively owns the native AUTH_SYS handle. It
        // is never published to the application and outlives all marshaling.
        unsafe { ((*(*self.0).operations).destroy)(self.0) };
    }
}

struct BroadcastResult {
    callback: Codec,
    pointer: *mut c_void,
}
impl Drop for BroadcastResult {
    fn drop(&mut self) {
        // SAFETY: XDR_FREE needs no backing byte stream. The application keeps
        // its result object live for the entire call. Cleanup also runs if a
        // decoder or eachresult callback throws or calls pthread_exit, and
        // releases partially decoded objects when a codec returns failure.
        let mut stream: Xdr = unsafe { std::mem::zeroed() };
        stream.x_op = XDR_FREE;
        unsafe { (self.callback)((&mut stream as *mut Xdr).cast(), self.pointer) };
    }
}

fn broadcast_addresses() -> Result<Vec<libc::sockaddr_in>, RpcError> {
    struct Addresses(*mut c_void);
    impl Drop for Addresses {
        fn drop(&mut self) {
            // SAFETY: the list was allocated by the paired native enumerator.
            unsafe { crate::unistd_abi::freeifaddrs(self.0) };
        }
    }
    let mut list = Addresses(ptr::null_mut());
    // SAFETY: the native enumerator writes one live pointer-sized stack slot.
    if unsafe { crate::unistd_abi::getifaddrs(&mut list.0) } != 0 {
        return Err(RpcError::status(3));
    }
    let mut destinations = Vec::new();
    let mut next = list.0.cast::<libc::ifaddrs>();
    while !next.is_null() {
        // SAFETY: every node and sockaddr belongs to the retained native list.
        let interface = unsafe { &*next };
        if interface.ifa_flags & (libc::IFF_UP | libc::IFF_BROADCAST) as u32
            == (libc::IFF_UP | libc::IFF_BROADCAST) as u32
            && !interface.ifa_addr.is_null()
            && !interface.ifa_ifu.is_null()
            && unsafe { (*interface.ifa_addr).sa_family as c_int } == libc::AF_INET
            && unsafe { (*interface.ifa_ifu).sa_family as c_int } == libc::AF_INET
        {
            // SAFETY: this list node carries an initialized IPv4 broadcast
            // sockaddr. Copy it before releasing the interface-list owner.
            let mut address = unsafe { interface.ifa_ifu.cast::<libc::sockaddr_in>().read() };
            address.sin_port = 111u16.to_be();
            destinations
                .try_reserve(1)
                .map_err(|_| RpcError::system(RPC_SYSTEMERROR, libc::ENOMEM))?;
            destinations.push(address);
        }
        next = interface.ifa_next;
    }
    Ok(destinations)
}

#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn broadcast(
    program: u64,
    version: u64,
    procedure: u64,
    arguments: *mut c_void,
    argument: *mut c_void,
    results: *mut c_void,
    result: *mut c_void,
    each: *mut c_void,
) -> c_int {
    let (_, decision) =
        super::super::runtime_policy::decide(ApiFamily::Socket, 0, 0, false, true, 0);
    let outcome = (|| -> Result<c_int, RpcError> {
        if matches!(decision.action, MembraneAction::Deny) {
            return Err(RpcError::system(RPC_SYSTEMERROR, libc::EACCES));
        }
        if arguments.is_null() {
            return Ok(1);
        }
        if !each.is_null() && results.is_null() {
            return Ok(2);
        }
        // CALLIT encodes these identifiers with GNU xdr_u_long, which rejects
        // values outside the 32-bit wire domain before invoking the argument
        // codec. This differs from the ordinary fixed RPC call-header encoder.
        if program > u32::MAX as u64 || version > u32::MAX as u64 || procedure > u32::MAX as u64 {
            return Ok(1);
        }
        let socket = Socket::open().map_err(|_| RpcError::status(3))?;
        let enabled: c_int = 1;
        // SAFETY: the socket is owned and the option points to one live int.
        unsafe {
            raw::sys_setsockopt(
                socket.fd,
                libc::SOL_SOCKET,
                libc::SO_BROADCAST,
                (&enabled as *const c_int).cast(),
                size_of::<c_int>(),
            )
        }
        .map_err(|_| RpcError::status(3))?;
        let destinations = broadcast_addresses()?;
        let auth = unsafe { super::authunix_create_default() }.cast::<Auth>();
        if auth.is_null() {
            return Err(RpcError::status(RPC_SYSTEMERROR));
        }
        let auth = BroadcastAuth(auth);
        let mut packet = buffer(BROADCAST_BUFFER)?;
        let mut received = buffer(BROADCAST_BUFFER)?;
        let xid = transaction_id();
        wire::encode_call_prefix(&mut packet, xid, PORTMAPPER as u32, VERSION as u32, 5)
            .map_err(|_| RpcError::status(1))?;
        // SAFETY: both streams start initialized and reference owned buffers.
        let mut stream: Xdr = unsafe { std::mem::zeroed() };
        unsafe {
            super::super::xdrmem_create(
                (&mut stream as *mut Xdr).cast(),
                packet.as_mut_ptr().add(wire::CALL_PREFIX_BYTES).cast(),
                (packet.len() - wire::CALL_PREFIX_BYTES) as c_uint,
                XDR_ENCODE,
            )
        };
        if stream.x_ops.is_null() {
            return Ok(1);
        }
        let mut args = Arguments {
            program,
            version,
            procedure,
            // SAFETY: the non-null callback follows the public XDR ABI; the
            // unwind-capable type preserves C++ and pthread_exit cleanup.
            callback: unsafe { std::mem::transmute::<*mut c_void, Codec>(arguments) },
            pointer: argument,
        };
        if unsafe { ((*(*auth.0).operations).marshal)(auth.0, &mut stream) } == 0
            || unsafe {
                remote_arguments(
                    (&mut stream as *mut Xdr).cast(),
                    (&mut args as *mut Arguments).cast(),
                )
            } == 0
        {
            return Ok(1);
        }
        let length = wire::CALL_PREFIX_BYTES
            .checked_add(unsafe { super::super::mem_pos(&stream) } as usize)
            .filter(|&length| length <= packet.len())
            .ok_or_else(|| RpcError::status(1))?;
        let started = monotonic()?;
        let mut elapsed = 0u64;
        for interval in [4u64, 6, 8, 10, 12, 14] {
            for address in &destinations {
                // SAFETY: both the exact encoded packet and copied sockaddr
                // stay live through this nonblocking datagram send.
                let sent = unsafe {
                    raw::sys_sendto(
                        socket.fd,
                        packet.as_ptr(),
                        length,
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        (address as *const libc::sockaddr_in).cast(),
                        size_of::<libc::sockaddr_in>(),
                    )
                }
                .map_err(|_| RpcError::status(3))?;
                if sent as usize != length {
                    return Ok(3);
                }
            }
            if each.is_null() {
                return Ok(0);
            }
            elapsed += interval * super::SECOND;
            let deadline = started.saturating_add(elapsed);
            loop {
                let now = monotonic()?;
                if now >= deadline {
                    break;
                }
                let mut poll = libc::pollfd {
                    fd: socket.fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let wait = (deadline - now).div_ceil(1_000_000).min(c_int::MAX as u64) as c_int;
                // SAFETY: poll owns its live stack slot. Socket/auth/buffer
                // guards remain active across the foreign cancellation edge.
                let ready = unsafe {
                    crate::pthread_abi::at_cancellation_point(|| {
                        raw::sys_poll((&mut poll as *mut libc::pollfd).cast(), 1, wait)
                    })
                };
                match ready {
                    Ok(0) | Err(libc::EINTR) => continue,
                    Err(_) => return Ok(4),
                    Ok(_) => {}
                }
                let mut peer: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                let mut peer_length = size_of::<libc::sockaddr_in>() as libc::socklen_t;
                // SAFETY: the kernel receives only owned bounded output areas.
                let count = match unsafe {
                    raw::sys_recvfrom(
                        socket.fd,
                        received.as_mut_ptr(),
                        received.len(),
                        libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                        (&mut peer as *mut libc::sockaddr_in).cast(),
                        &mut peer_length,
                    )
                } {
                    Ok(count) => count as usize,
                    Err(libc::EAGAIN | libc::EINTR) => continue,
                    Err(_) => return Ok(4),
                };
                if count > received.len()
                    || count < 4
                    || peer_length as usize != size_of::<libc::sockaddr_in>()
                    || peer.sin_family as c_int != libc::AF_INET
                {
                    continue;
                }
                let received_xid = u32::from_be_bytes(received[..4].try_into().unwrap());
                let Ok(Reply::Success { results: range, .. }) =
                    wire::decode_reply(&received[..count], received_xid)
                else {
                    continue;
                };
                // SAFETY: each and results were checked above. Both remain
                // live application callbacks until this operation returns.
                let callback = unsafe { std::mem::transmute::<*mut c_void, EachResult>(each) };
                let codec = unsafe { std::mem::transmute::<*mut c_void, Codec>(results) };
                let mut port = 0u64;
                let mut output = Results {
                    port: &mut port,
                    callback: codec,
                    pointer: result,
                };
                unsafe {
                    super::super::xdrmem_create(
                        (&mut stream as *mut Xdr).cast(),
                        received.as_mut_ptr().add(range.start).cast(),
                        range.len() as c_uint,
                        XDR_DECODE,
                    )
                };
                if stream.x_ops.is_null() {
                    return Ok(2);
                }
                let cleanup = BroadcastResult {
                    callback: codec,
                    pointer: result,
                };
                let decoded = unsafe {
                    remote_results(
                        (&mut stream as *mut Xdr).cast(),
                        (&mut output as *mut Results).cast(),
                    )
                } != 0;
                // GNU decodes/frees each successful RPC envelope before
                // checking its transaction ID. Preserve codec side effects,
                // but never deliver a stale response to the result callback.
                if decoded && received_xid == xid {
                    peer.sin_port = (port as u16).to_be();
                    // SAFETY: peer and decoded result remain live until the
                    // callback returns; cleanup then releases result storage.
                    if unsafe { callback(result, &mut peer) } != 0 {
                        drop(cleanup);
                        return Ok(0);
                    }
                }
                drop(cleanup);
            }
        }
        Ok(5)
    })();
    let status = outcome.unwrap_or_else(|error| error.status);
    super::super::runtime_policy::observe(ApiFamily::Socket, decision.profile, 100, status != 0);
    status
}
