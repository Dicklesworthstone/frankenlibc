//! Native portmapper DUMP and CALLIT clients.
//!
//! Both operations reuse the native CLIENT transport, callbacks and deadline
//! machinery. No rpcbind daemon is embedded and no host RPC function is called.
//! DUMP uses TCP; CALLIT uses UDP and preserves GNU's callback-visible port
//! publication and caller-address reset behavior.

use super::super::{Pmap, PmapList, XDR_DECODE, XDR_ENCODE, XDR_TRUE};
use super::{
    Client, CreateFailure, MAX_STREAM_BUFFER, Network, RPC_SYSTEMERROR, RpcError, Timeval, Xdr,
    XdrProc, call, creation_error, destroy, import, make_client, nanos, publish,
};
use frankenlibc_core::rpc::wire::portmap::{MappingError, decode_mappings};
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
