//! Reliable RPC transport shared by the native CLIENT implementation.
//!
//! Record state survives receive timeouts. A partial request write or malformed
//! framing poisons the transport: silently replaying a possibly executed RPC on a
//! fresh connection would be unsafe for non-idempotent procedures. Borrowed file
//! descriptors keep their file flags and are never reconnected or shut down.
//! Unix clients enable SO_PASSCRED; the caller still owns a borrowed descriptor.

use super::super::rpc_svc::{UnixCredential, unix_receive, unix_send};
use super::{Deadline, RpcError, SECOND, Socket, kernel, monotonic};
use frankenlibc_core::rpc::wire::records::{RecordDecoder, RecordError, fragment_header};
use frankenlibc_core::syscall as raw;
use std::ffi::c_int;
use std::mem::size_of;

const CONNECT_TIMEOUT: u64 = 30 * SECOND;
const MAX_FRAGMENTS: usize = 4096;

pub(super) struct Stream {
    pub(super) unix: bool,
    decoder: RecordDecoder,
    input: [u8; 4096],
    start: usize,
    end: usize,
    failure: Option<RpcError>,
    chunk_credential: Option<UnixCredential>,
    record_credential: Option<UnixCredential>,
}

impl Stream {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            unix: false,
            decoder: RecordDecoder::new(limit, MAX_FRAGMENTS),
            input: [0; 4096],
            start: 0,
            end: 0,
            failure: None,
            chunk_credential: None,
            record_credential: None,
        }
    }

    fn poison<T>(&mut self, error: RpcError) -> Result<T, RpcError> {
        self.failure = Some(error);
        Err(error)
    }

    pub(super) fn exchange(
        &mut self,
        socket: &Socket,
        request: &[u8],
        response: &mut [u8],
        xid: u32,
        budget: Deadline,
    ) -> Result<usize, RpcError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let deadline = budget.at;
        let marker = fragment_header(request.len(), true).map_err(record_error)?;
        let mut sent = 0;
        for bytes in [marker.as_slice(), request] {
            let mut offset = 0;
            while offset < bytes.len() {
                // A zero timeout may send a complete call, as the UDP client
                // does, but must never block. Check the same deadline on EINTR,
                // short writes and EAGAIN rather than renewing a relative wait.
                let now = match monotonic() {
                    Ok(now) => now,
                    Err(error) => {
                        return if sent == 0 {
                            Err(error)
                        } else {
                            self.poison(error)
                        };
                    }
                };
                if !budget.nonblocking && now >= deadline {
                    let error = RpcError::status(5);
                    return if sent == 0 {
                        Err(error)
                    } else {
                        self.poison(error)
                    };
                }
                // SAFETY: the exact remaining initialized slice is submitted;
                // MSG_NOSIGNAL contains peer-close errors within this operation.
                let result = if self.unix {
                    unix_send(socket.fd, &bytes[offset..]).map(|count| count as usize)
                } else {
                    // SAFETY: the retained request slice outlives this send.
                    kernel(unsafe {
                        raw::syscall6(
                            libc::SYS_sendto as usize,
                            socket.fd as usize,
                            bytes[offset..].as_ptr() as usize,
                            bytes.len() - offset,
                            (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as usize,
                            0,
                            0,
                        )
                    })
                };
                match result {
                    Ok(0) => return self.poison(RpcError::system(3, libc::EPIPE)),
                    Ok(count) => {
                        offset += count;
                        sent += count;
                    }
                    Err(libc::EINTR) => {
                        if budget.nonblocking {
                            let error = RpcError::status(5);
                            return if sent == 0 {
                                Err(error)
                            } else {
                                self.poison(error)
                            };
                        }
                    }
                    Err(libc::EAGAIN) => {
                        if let Err(error) = wait(socket.fd, libc::POLLOUT, deadline, 3) {
                            return if sent == 0 {
                                Err(error)
                            } else {
                                self.poison(error)
                            };
                        }
                    }
                    Err(error) => return self.poison(RpcError::system(3, error)),
                }
            }
        }
        loop {
            if monotonic()? >= deadline {
                // A complete request is already on the stream. Keep a partial
                // reply for the next call, which will discard its stale XID.
                return Err(RpcError::status(5));
            }
            if self.start < self.end {
                if self.unix {
                    if let Some(previous) = self.record_credential {
                        if Some(previous) != self.chunk_credential {
                            return self.poison(RpcError::system(4, libc::EPROTO));
                        }
                    } else {
                        self.record_credential = self.chunk_credential;
                    }
                }
                let used = match self.decoder.consume(&self.input[self.start..self.end]) {
                    Ok(used) => used,
                    Err(error) => return self.poison(record_error(error)),
                };
                self.start += used;
                if let Some(record) = self.decoder.record() {
                    self.record_credential = None;
                    if record.len() < 4 {
                        self.decoder.discard_record();
                        return Err(RpcError::system(2, libc::EPROTO));
                    }
                    if record[..4] == xid.to_be_bytes() {
                        if record.len() > response.len() {
                            return self.poison(RpcError::system(2, libc::EMSGSIZE));
                        }
                        let length = record.len();
                        response[..length].copy_from_slice(record);
                        self.decoder.discard_record();
                        return Ok(length);
                    }
                    self.decoder.discard_record();
                }
                continue;
            }
            match wait(socket.fd, libc::POLLIN, deadline, 4) {
                Ok(()) => {}
                Err(error) if error.status == 5 => return Err(error),
                Err(error) => return self.poison(error),
            }
            // SAFETY: recv writes at most input.len() bytes to owned storage.
            let received = if self.unix {
                unix_receive(socket.fd, &mut self.input).map(|(count, credential)| {
                    self.chunk_credential = Some(credential);
                    count as usize
                })
            } else {
                // SAFETY: input is owned writable scratch of exactly this length.
                kernel(unsafe {
                    raw::syscall6(
                        libc::SYS_recvfrom as usize,
                        socket.fd as usize,
                        self.input.as_mut_ptr() as usize,
                        self.input.len(),
                        libc::MSG_DONTWAIT as usize,
                        0,
                        0,
                    )
                })
            };
            match received {
                Ok(0) => {
                    let error = match self.decoder.finish() {
                        Ok(()) => RpcError::system(4, libc::ECONNRESET),
                        Err(error) => record_error(error),
                    };
                    return self.poison(error);
                }
                Ok(count) => {
                    self.start = 0;
                    self.end = count;
                }
                Err(libc::EINTR) | Err(libc::EAGAIN) => {}
                Err(error) => return self.poison(RpcError::system(4, error)),
            }
        }
    }
}

fn record_error(error: RecordError) -> RpcError {
    match error {
        RecordError::TooLarge => RpcError::system(2, libc::EMSGSIZE),
        RecordError::TooManyFragments => RpcError::system(2, libc::EPROTO),
        RecordError::Allocation => RpcError::system(12, libc::ENOMEM),
        RecordError::Truncated => RpcError::system(4, libc::ECONNRESET),
    }
}

/// Poll readiness with an absolute monotonic deadline. Readiness errors are
/// handled by the subsequent send/recv/SO_ERROR operation, not mistaken for EOF.
fn wait(fd: c_int, events: i16, deadline: u64, status: c_int) -> Result<(), RpcError> {
    loop {
        let now = monotonic()?;
        if now >= deadline {
            return Err(RpcError::status(5));
        }
        let left = deadline - now;
        let mut interval = libc::timespec {
            tv_sec: (left / SECOND) as libc::time_t,
            tv_nsec: (left % SECOND) as libc::c_long,
        };
        let mut pollfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: ppoll accesses only these live stack objects. No signal-mask
        // change or file-status flag change is performed.
        match kernel(unsafe {
            raw::syscall5(
                libc::SYS_ppoll as usize,
                (&mut pollfd as *mut libc::pollfd) as usize,
                1,
                (&mut interval as *mut libc::timespec) as usize,
                0,
                8,
            )
        }) {
            Err(libc::EINTR) | Ok(0) => continue,
            Err(error) => return Err(RpcError::system(status, error)),
            Ok(_) => {}
        }
        if pollfd.revents & libc::POLLNVAL != 0 {
            return Err(RpcError::system(status, libc::EBADF));
        }
        if pollfd.revents & (events | libc::POLLERR | libc::POLLHUP) != 0 {
            return Ok(());
        }
    }
}

fn option(fd: c_int, name: c_int) -> Result<c_int, RpcError> {
    let mut value: c_int = 0;
    let mut length = size_of::<c_int>() as libc::socklen_t;
    // SAFETY: both output scalars are initialized and correctly sized.
    kernel(unsafe {
        raw::syscall5(
            libc::SYS_getsockopt as usize,
            fd as usize,
            libc::SOL_SOCKET as usize,
            name as usize,
            (&mut value as *mut c_int) as usize,
            (&mut length as *mut libc::socklen_t) as usize,
        )
    })
    .map_err(|error| RpcError::system(12, error))?;
    if length as usize != size_of::<c_int>() {
        return Err(RpcError::system(12, libc::EINVAL));
    }
    Ok(value)
}

pub(super) fn connect(peer: &libc::sockaddr_in, fd: c_int) -> Result<Socket, RpcError> {
    connect_address(
        (peer as *const libc::sockaddr_in).cast(),
        size_of::<libc::sockaddr_in>(),
        libc::AF_INET,
        fd,
    )
}

pub(super) fn connect_unix(peer: &libc::sockaddr_un, fd: c_int) -> Result<Socket, RpcError> {
    let length = if fd < 0 {
        let length = peer
            .sun_path
            .iter()
            .position(|&byte| byte == 0)
            .filter(|&length| length != 0)
            .ok_or_else(|| RpcError::system(12, libc::ENAMETOOLONG))?;
        size_of::<libc::sa_family_t>() + length + 1
    } else {
        size_of::<libc::sockaddr_un>()
    };
    // GNU Unix constructors accept any negative descriptor as an allocation
    // request. Supplied connected sockets are borrowed without reconnecting.
    let socket = connect_address(
        (peer as *const libc::sockaddr_un).cast(),
        length,
        libc::AF_UNIX,
        if fd < 0 { -1 } else { fd },
    )?;
    let enabled = 1i32;
    // SAFETY: the kernel only reads the owned initialized option scalar.
    unsafe {
        raw::sys_setsockopt(
            socket.fd,
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enabled as *const i32).cast(),
            size_of::<i32>(),
        )
    }
    .map_err(|error| RpcError::system(12, error))?;
    Ok(socket)
}

// Only the two typed wrappers call this, with a live copied address and length.
fn connect_address(
    address: *const u8,
    length: usize,
    family: c_int,
    fd: c_int,
) -> Result<Socket, RpcError> {
    if fd != -1 {
        if option(fd, libc::SO_TYPE)? != libc::SOCK_STREAM || option(fd, libc::SO_DOMAIN)? != family
        {
            return Err(RpcError::system(12, libc::EPROTOTYPE));
        }
        // SAFETY: zero initializes writable storage for either peer family.
        let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        // SAFETY: caller sockets must already be connected, matching clnttcp's
        // borrowed-descriptor contract. Probe with owned output storage only.
        kernel(unsafe {
            raw::syscall3(
                libc::SYS_getpeername as usize,
                fd as usize,
                (&mut peer as *mut libc::sockaddr_storage) as usize,
                (&mut length as *mut libc::socklen_t) as usize,
            )
        })
        .map_err(|error| RpcError::system(12, error))?;
        return Ok(Socket { fd, owned: false });
    }
    // The nonblocking flag is private until the descriptor is published. Once
    // connected, restore blocking mode; per-call MSG_DONTWAIT governs IO.
    let fd = kernel(unsafe {
        raw::syscall3(
            libc::SYS_socket as usize,
            family as usize,
            (libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as usize,
            0,
        )
    })
    .map_err(|error| RpcError::system(12, error))? as c_int;
    let socket = Socket { fd, owned: true };
    let deadline = monotonic()?
        .checked_add(CONNECT_TIMEOUT)
        .ok_or_else(|| RpcError::system(12, libc::EOVERFLOW))?;
    // SAFETY: the typed wrapper retains the complete validated copied address.
    match kernel(unsafe {
        raw::syscall3(
            libc::SYS_connect as usize,
            fd as usize,
            address as usize,
            length,
        )
    }) {
        Ok(_) => {}
        Err(libc::EINPROGRESS) | Err(libc::EINTR) => {
            wait(fd, libc::POLLOUT, deadline, 12)?;
            let error = option(fd, libc::SO_ERROR)?;
            if error != 0 {
                return Err(RpcError::system(12, error));
            }
        }
        Err(error) => return Err(RpcError::system(12, error)),
    }
    let flags = kernel(unsafe {
        raw::syscall3(
            libc::SYS_fcntl as usize,
            fd as usize,
            libc::F_GETFL as usize,
            0,
        )
    })
    .map_err(|error| RpcError::system(12, error))?;
    kernel(unsafe {
        raw::syscall3(
            libc::SYS_fcntl as usize,
            fd as usize,
            libc::F_SETFL as usize,
            flags & !(libc::O_NONBLOCK as usize),
        )
    })
    .map_err(|error| RpcError::system(12, error))?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::super::{Client, Timeval, XdrProc, call, control, create_tcp, destroy, geterr};
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddrV4, TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::sync::mpsc;
    use std::time::Duration;

    fn listener() -> (TcpListener, libc::sockaddr_in) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            panic!("IPv4");
        };
        (listener, address_of(address))
    }
    fn address_of(address: SocketAddrV4) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: address.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(address.ip().octets()),
            },
            sin_zero: [0; 8],
        }
    }
    fn accept(listener: TcpListener) -> TcpStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    return stream;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "accept timed out");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("accept: {error}"),
            }
        }
    }
    fn read_call(stream: &mut TcpStream) -> Vec<u8> {
        let mut marker = [0; 4];
        stream.read_exact(&mut marker).unwrap();
        let value = u32::from_be_bytes(marker);
        assert_ne!(value & 0x8000_0000, 0);
        let count = (value & 0x7fff_ffff) as usize;
        assert!((40..=100_000).contains(&count));
        let mut request = vec![0; count];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request[4..12], &[0, 0, 0, 0, 0, 0, 0, 2]);
        request
    }
    fn reply(xid: &[u8], words: &[u32]) -> Vec<u8> {
        let mut payload = xid.to_vec();
        for word in words {
            payload.extend_from_slice(&word.to_be_bytes());
        }
        let mut result = fragment_header(payload.len(), true).unwrap().to_vec();
        result.extend(payload);
        result
    }
    unsafe extern "C" fn codec(xdr: *mut std::ffi::c_void, value: *mut std::ffi::c_void) -> c_int {
        unsafe { super::super::super::xdr_u_int(xdr, value.cast()) }
    }
    fn client(
        peer: &mut libc::sockaddr_in,
        fd: &mut c_int,
        send: u32,
        receive: u32,
    ) -> *mut Client {
        let pointer = unsafe {
            create_tcp(
                (peer as *mut libc::sockaddr_in).cast(),
                77,
                1,
                fd,
                send,
                receive,
            )
        };
        assert!(!pointer.is_null(), "native TCP CLIENT creation failed");
        pointer.cast()
    }
    unsafe fn invoke(client: *mut Client, micros: i64, result: &mut u32) -> c_int {
        let mut argument = 41u32;
        unsafe {
            call(
                client,
                3,
                Some(codec as XdrProc),
                (&mut argument as *mut u32).cast(),
                Some(codec as XdrProc),
                (result as *mut u32).cast(),
                Timeval {
                    tv_sec: micros / 1_000_000,
                    tv_usec: micros % 1_000_000,
                },
            )
        }
    }

    #[test]
    fn tcp_client_fragmented_reply_stale_xid_and_remote_error() {
        let (listener, mut peer) = listener();
        let server = std::thread::spawn(move || {
            let mut stream = accept(listener);
            let request = read_call(&mut stream);
            assert_eq!(&request[40..], &41u32.to_be_bytes());
            let xid = u32::from_be_bytes(request[..4].try_into().unwrap());
            let stale = reply(&xid.wrapping_sub(1).to_be_bytes(), &[1, 0, 0, 0, 0, 999]);
            let valid = reply(&request[..4], &[1, 0, 0, 0, 0, 42]);
            stream.write_all(&stale).unwrap();
            // Split the RPC payload across fragments and every marker across
            // individual writes, not merely at naturally aligned word edges.
            for (part, last) in [(&valid[4..5], false), (&valid[5..], true)] {
                for byte in fragment_header(part.len(), last)
                    .unwrap()
                    .iter()
                    .chain(part)
                {
                    stream.write_all(&[*byte]).unwrap();
                }
            }
            let request = read_call(&mut stream);
            stream
                .write_all(&reply(&request[..4], &[1, 0, 0, 0, 2, 2, 6]))
                .unwrap();
        });
        let mut fd = -1;
        let client = client(&mut peer, &mut fd, 0, 0);
        let mut result = 0;
        unsafe {
            assert_eq!(invoke(client, 2_000_000, &mut result), 0);
            assert_eq!(result, 42);
            assert_eq!(invoke(client, 2_000_000, &mut result), 9);
            let mut error = RpcError::status(0);
            geterr(client, &mut error);
            assert_eq!(error.status, 9);
            assert_eq!(u64::from_ne_bytes(error.detail[..8].try_into().unwrap()), 2);
            assert_eq!(u64::from_ne_bytes(error.detail[8..].try_into().unwrap()), 6);
            destroy(client);
        }
        server.join().unwrap();
    }

    #[test]
    fn tcp_timeout_keeps_partial_marker_and_discards_the_late_reply() {
        let (listener, mut peer) = listener();
        let (release, resume) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let mut stream = accept(listener);
            let request = read_call(&mut stream);
            let late = reply(&request[..4], &[1, 0, 0, 0, 0, 99]);
            stream.write_all(&late[..2]).unwrap();
            resume.recv_timeout(Duration::from_secs(3)).unwrap();
            stream.write_all(&late[2..]).unwrap();
            let request = read_call(&mut stream);
            stream
                .write_all(&reply(&request[..4], &[1, 0, 0, 0, 0, 42]))
                .unwrap();
        });
        let mut fd = -1;
        let client = client(&mut peer, &mut fd, 0, 0);
        let mut result = 0;
        unsafe {
            assert_eq!(invoke(client, 100_000, &mut result), 5);
            release.send(()).unwrap();
            assert_eq!(invoke(client, 2_000_000, &mut result), 0);
            assert_eq!(result, 42);
            destroy(client);
        }
        server.join().unwrap();
    }

    #[test]
    fn oversized_record_poisoning_prevents_request_replay() {
        let (listener, mut peer) = listener();
        let server = std::thread::spawn(move || {
            let mut stream = accept(listener);
            read_call(&mut stream);
            stream
                .write_all(&fragment_header(65, true).unwrap())
                .unwrap();
            let mut byte = [0];
            assert_eq!(
                stream.read(&mut byte).unwrap(),
                0,
                "a poisoned client replayed a request"
            );
        });
        let mut fd = -1;
        let client = client(&mut peer, &mut fd, 0, 64);
        let mut result = 0;
        unsafe {
            assert_eq!(invoke(client, 2_000_000, &mut result), 2);
            assert_eq!(invoke(client, 2_000_000, &mut result), 2);
            destroy(client);
        }
        server.join().unwrap();
    }

    #[test]
    fn borrowed_tcp_descriptor_keeps_flags_and_ownership() {
        let (listener, mut peer) = listener();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _server = accept(listener);
        stream.set_nonblocking(true).unwrap();
        let mut fd = stream.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let client = client(&mut peer, &mut fd, 0, 0);
        unsafe {
            let mut returned = -1;
            assert_eq!(control(client, 6, (&mut returned as *mut c_int).cast()), 1);
            assert_eq!(returned, fd);
            assert_eq!(
                control(client, 4, std::ptr::null_mut()),
                0,
                "TCP has no UDP retry timer"
            );
            destroy(client);
            assert_eq!(libc::fcntl(fd, libc::F_GETFL), flags);
        }
    }

    #[test]
    fn truncated_reply_is_sticky_and_never_decodes_partial_results() {
        let (listener, mut peer) = listener();
        let server = std::thread::spawn(move || {
            let mut stream = accept(listener);
            let request = read_call(&mut stream);
            let response = reply(&request[..4], &[1, 0, 0, 0, 0, 42]);
            stream.write_all(&response[..response.len() - 1]).unwrap();
        });
        let mut fd = -1;
        let client = client(&mut peer, &mut fd, 0, 0);
        let mut result = 123;
        unsafe {
            assert_eq!(invoke(client, 2_000_000, &mut result), 4);
            assert_eq!(result, 123);
            assert_eq!(invoke(client, 2_000_000, &mut result), 4);
            destroy(client);
        }
        server.join().unwrap();
    }
}
