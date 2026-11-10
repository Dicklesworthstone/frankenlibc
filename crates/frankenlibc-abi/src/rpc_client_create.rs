//! Native hostname/pathname-based RPC client creation and one-shot calls.
//! Reuse the native resolver, portmapper, transport and codec ownership paths.
//! No host RPC delegation or process-global client cache.

use super::{
    __rpc_thread_createerr, Timeval, XdrProc, c_char, c_int, c_uint, c_ulong, c_void,
    read_bounded_cstr, rpc_udp, set_abi_errno,
};

/// Create a native RPC client using UDP/TCP host lookup or a Unix socket path.
/// IP transports own portmapper discovery; Unix clients connect directly to the
/// supplied pathname. Clients own their sockets and publish detailed creation errors.
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
        Some(name) if name == b"unix" => return unsafe { create_unix(host, prog, vers) },
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

unsafe fn create_unix(path: *const c_char, program: c_ulong, version: c_ulong) -> *mut c_void {
    // SAFETY: every field in sockaddr_un admits zero, including its path terminator.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let (length, terminated) = if path.is_null() {
        (0, false)
    } else {
        // SAFETY: the caller supplies a C pathname. Inspect at most sun_path's
        // capacity, byte by byte, so rejection never reads beyond that bound.
        unsafe { crate::util::scan_c_string(path, Some(address.sun_path.len())) }
    };
    if !terminated {
        // GNU rejects paths that leave no room for the terminating NUL before
        // creating a socket. Only cf_stat and re_errno replace prior TLS state.
        rpc_udp::creation_status_preserving_details(12, Some(libc::EINVAL));
        set_abi_errno(libc::EINVAL);
        return std::ptr::null_mut();
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // SAFETY: the bounded scan established exactly length readable path bytes.
    let bytes = unsafe { std::slice::from_raw_parts(path.cast::<u8>(), length) };
    for (destination, byte) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *byte as c_char;
    }
    let mut descriptor = -1;
    // SAFETY: the transport imports this fully initialized local address and
    // descriptor, then owns the socket it creates. Neither pointer escapes.
    let client = unsafe {
        rpc_udp::create_unix(
            (&mut address as *mut libc::sockaddr_un).cast(),
            program,
            version,
            &mut descriptor,
            0,
            0,
        )
    };
    if client.is_null() {
        let (status, _, details) = rpc_udp::creation_error_details();
        if status == 12 {
            // Raw transport syscalls return errors without writing libc errno.
            // Publish the Unix constructor's system error through both APIs.
            let bytes = details[0].to_ne_bytes();
            set_abi_errno(c_int::from_ne_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ]));
        }
    }
    client
}

/// Resolve the first legacy IPv4 host address and query its native portmapper.
/// Reentrant host lookup preserves hostname acceptance and address ordering;
/// all returned pointers remain owned by this call's scratch buffer.
pub(super) unsafe fn getrpcport(
    host: *const c_char,
    program: c_ulong,
    version: c_ulong,
    protocol: c_uint,
) -> c_int {
    if host.is_null() {
        rpc_udp::creation_status_preserving_details(13, None); // RPC_UNKNOWNHOST
        return 0;
    }
    let mut local = [0u8; 1024];
    let mut grown = Vec::<u8>::new();
    loop {
        let buffer = if grown.is_empty() {
            &mut local[..]
        } else {
            grown.as_mut_slice()
        };
        let mut hostent: libc::hostent = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let mut host_error = 0;
        // SAFETY: host has the caller's C-string contract; every output and
        // the scratch buffer are writable and remain live through the lookup.
        let status = unsafe {
            crate::unistd_abi::gethostbyname2_r(
                host,
                libc::AF_INET,
                &mut hostent,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
                &mut host_error,
            )
        };
        // The native reentrant API returns ERANGE for a short scratch buffer
        // while preserving h_errno and errno. Its return code drives growth.
        if status == libc::ERANGE {
            let Some(length) = buffer.len().checked_mul(2) else {
                rpc_udp::creation_status_preserving_details(12, Some(libc::ENOMEM));
                return 0;
            };
            if grown.try_reserve_exact(length - grown.len()).is_err() {
                rpc_udp::creation_status_preserving_details(12, Some(libc::ENOMEM));
                return 0;
            }
            grown.resize(length, 0);
            continue;
        }
        if status != 0 || result.is_null() {
            rpc_udp::creation_status_preserving_details(13, None);
            return 0;
        }
        // SAFETY: a successful native lookup returns the owned hostent above.
        let entry = unsafe { &*result };
        if entry.h_addrtype != libc::AF_INET || entry.h_length != 4 {
            rpc_udp::creation_status_preserving_details(12, Some(libc::EAFNOSUPPORT));
            return 0;
        }
        if entry.h_addr_list.is_null() {
            rpc_udp::creation_status_preserving_details(13, None);
            return 0;
        }
        // SAFETY: the native resolver returns a terminated address-pointer array.
        let first = unsafe { entry.h_addr_list.read() };
        if first.is_null() {
            rpc_udp::creation_status_preserving_details(13, None);
            return 0;
        }
        let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        address.sin_family = libc::AF_INET as libc::sa_family_t;
        // SAFETY: the IPv4 hostent supplies four readable network-order bytes.
        address.sin_addr = unsafe { first.cast::<libc::in_addr>().read_unaligned() };
        // SAFETY: the copied address is private and writable for this query.
        return unsafe {
            rpc_udp::getport(
                (&mut address as *mut libc::sockaddr_in).cast(),
                program,
                version,
                protocol,
            ) as c_int
        };
    }
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
