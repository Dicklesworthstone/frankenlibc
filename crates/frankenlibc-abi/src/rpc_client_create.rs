//! Native hostname-based RPC client creation and one-shot calls.
//! Reuse the native resolver, portmapper, transport and codec ownership paths.
//! No host RPC delegation or process-global client cache.

use super::{
    __rpc_thread_createerr, Timeval, XdrProc, c_char, c_int, c_ulong, c_void, read_bounded_cstr,
    rpc_udp, set_abi_errno,
};

/// Create an IPv4 RPC client using the native resolver and UDP/TCP transports.
/// The transport owns portmapper discovery and publishes its detailed creation
/// error. Neither a host RPC constructor nor a borrowed address list is used.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_create(
    host: *const c_char,
    prog: c_ulong,
    vers: c_ulong,
    proto: *const c_char,
) -> *mut c_void {
    let protocol = match unsafe { read_bounded_cstr(proto) } {
        Some(name) if name == b"udp" => libc::IPPROTO_UDP,
        Some(name) if name == b"tcp" => libc::IPPROTO_TCP,
        _ => {
            rpc_udp::creation_status(17, libc::EPFNOSUPPORT); // RPC_UNKNOWNPROTO
            return std::ptr::null_mut();
        }
    };
    let name =
        unsafe { read_bounded_cstr(host) }.and_then(|bytes| std::ffi::CString::new(bytes).ok());
    let Some(name) = name else {
        rpc_udp::creation_status(13, 0); // RPC_UNKNOWNHOST
        return std::ptr::null_mut();
    };
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_INET;
    hints.ai_socktype = if protocol == libc::IPPROTO_UDP {
        libc::SOCK_DGRAM
    } else {
        libc::SOCK_STREAM
    };
    hints.ai_protocol = protocol;
    let mut result = std::ptr::null_mut();
    if unsafe {
        crate::resolv_abi::getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut result)
    } != 0
    {
        rpc_udp::creation_status(13, 0);
        return std::ptr::null_mut();
    }

    struct Addresses(*mut libc::addrinfo);
    impl Drop for Addresses {
        fn drop(&mut self) {
            // Match the native allocator, including early transport failure.
            // Preserve the constructor's errno; do not republish rpc_createerr.
            unsafe {
                let saved = *crate::errno_abi::__errno_location();
                crate::resolv_abi::freeaddrinfo(self.0);
                set_abi_errno(saved);
            }
        }
    }
    let addresses = Addresses(result);
    let mut current = addresses.0;
    while !current.is_null() {
        // SAFETY: this list was returned by the native resolver and remains
        // owned by `addresses` until the transport has copied the sockaddr.
        let entry = unsafe { &*current };
        if entry.ai_family == libc::AF_INET
            && !entry.ai_addr.is_null()
            && entry.ai_addrlen as usize >= std::mem::size_of::<libc::sockaddr_in>()
        {
            let mut address = unsafe { entry.ai_addr.cast::<libc::sockaddr_in>().read_unaligned() };
            address.sin_port = 0;
            let mut descriptor = -1; // Construct an owned, not borrowed, socket.
            return if protocol == libc::IPPROTO_UDP {
                unsafe {
                    rpc_udp::create(
                        (&mut address as *mut libc::sockaddr_in).cast(),
                        prog,
                        vers,
                        Timeval {
                            tv_sec: 5,
                            tv_usec: 0,
                        },
                        &mut descriptor,
                        0,
                        0,
                    )
                }
            } else {
                unsafe {
                    rpc_udp::create_tcp(
                        (&mut address as *mut libc::sockaddr_in).cast(),
                        prog,
                        vers,
                        &mut descriptor,
                        0,
                        0,
                    )
                }
            };
        }
        current = entry.ai_next;
    }
    rpc_udp::creation_status(13, 0);
    std::ptr::null_mut()
}

/// Execute a one-shot UDP RPC using the native CLIENT and XDR implementations.
/// The GNU LP64 ABI takes `unsigned long` identifiers. Discovery rejects a
/// program/version outside the 32-bit wire domain; the procedure uses its
/// low 32 bits, matching the GNU call header encoder.
/// Each call owns and retires its client; no process-global client cache or
/// lock is retained across application encoder/decoder callbacks.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn callrpc(
    host: *const c_char,
    prognum: c_ulong,
    versnum: c_ulong,
    procnum: c_ulong,
    inproc: *mut c_void,
    in_: *mut c_char,
    outproc: *mut c_void,
    out: *mut c_char,
) -> c_int {
    if host.is_null() {
        rpc_udp::creation_status(13, 0); // RPC_UNKNOWNHOST
        return 13;
    }
    // Reject missing codecs without constructing a client or issuing a call.
    // Other callback/data-pointer validity remains the C caller's contract.
    if inproc.is_null() {
        return 1; // RPC_CANTENCODEARGS
    }
    if outproc.is_null() {
        return 2; // RPC_CANTDECODERES
    }
    let client = unsafe { clnt_create(host, prognum, versnum, c"udp".as_ptr()) };
    if client.is_null() {
        // Native constructors publish the top-level discovery/transport status
        // together with the more detailed nested RPC error in this TLS slot.
        return unsafe { __rpc_thread_createerr().cast::<c_int>().read() };
    }
    // SAFETY: non-null C XDR callback pointers with the public two-operand ABI.
    let encode: XdrProc = unsafe { std::mem::transmute(inproc) };
    let decode: XdrProc = unsafe { std::mem::transmute(outproc) };
    unsafe {
        rpc_udp::call_once(
            client,
            procnum,
            Some(encode),
            in_.cast(),
            Some(decode),
            out.cast(),
        )
    }
}
