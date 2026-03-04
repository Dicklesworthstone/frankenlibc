//! ABI integration tests for socket_abi native implementations.
//!
//! Covers: socket, bind, listen, connect, send, recv, shutdown,
//! socketpair, getsockname, setsockopt, getsockopt, getpeername,
//! sendto, recvfrom, accept4.

#![allow(unsafe_code)]

use std::ffi::{c_int, c_void};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::socket_abi;
use frankenlibc_core::errno;

/// Close a file descriptor via libc syscall.
unsafe fn close_fd(fd: c_int) {
    unsafe { libc::syscall(libc::SYS_close, fd) };
}

// ---------------------------------------------------------------------------
// socket creation
// ---------------------------------------------------------------------------

#[test]
fn socket_tcp_creates_valid_fd() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "socket(AF_INET, SOCK_STREAM) should return valid fd, got {fd}");
    unsafe { close_fd(fd) };
}

#[test]
fn socket_udp_creates_valid_fd() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0, "socket(AF_INET, SOCK_DGRAM) should return valid fd, got {fd}");
    unsafe { close_fd(fd) };
}

#[test]
fn socket_unix_stream() {
    let fd = unsafe { socket_abi::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "socket(AF_UNIX, SOCK_STREAM) should return valid fd");
    unsafe { close_fd(fd) };
}

#[test]
fn socket_cloexec_flag() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0, "SOCK_CLOEXEC should not prevent creation");
    unsafe { close_fd(fd) };
}

// ---------------------------------------------------------------------------
// bind
// ---------------------------------------------------------------------------

#[test]
fn bind_invalid_fd_sets_ebadf_errno() {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;

    let rc = unsafe {
        socket_abi::bind(
            -1,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(rc, -1);

    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

#[test]
fn bind_loopback_succeeds() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0; // Let kernel pick a port
    addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);

    let rc = unsafe {
        socket_abi::bind(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(rc, 0, "bind to loopback with port 0 should succeed");
    unsafe { close_fd(fd) };
}

// ---------------------------------------------------------------------------
// listen
// ---------------------------------------------------------------------------

#[test]
fn listen_after_bind() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);

    let rc = unsafe {
        socket_abi::bind(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(rc, 0);

    let rc = unsafe { socket_abi::listen(fd, 5) };
    assert_eq!(rc, 0, "listen should succeed after bind");
    unsafe { close_fd(fd) };
}

// ---------------------------------------------------------------------------
// socketpair
// ---------------------------------------------------------------------------

#[test]
fn socketpair_unix_stream() {
    let mut sv = [0 as c_int; 2];
    let rc = unsafe {
        socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr())
    };
    assert_eq!(rc, 0, "socketpair(AF_UNIX, SOCK_STREAM) should succeed");
    assert!(sv[0] >= 0);
    assert!(sv[1] >= 0);
    assert_ne!(sv[0], sv[1]);
    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

#[test]
fn socketpair_send_recv() {
    let mut sv = [0 as c_int; 2];
    let rc = unsafe {
        socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr())
    };
    assert_eq!(rc, 0);

    // Send data through one end
    let msg = b"hello";
    let sent = unsafe {
        socket_abi::send(sv[0], msg.as_ptr() as *const c_void, msg.len(), 0)
    };
    assert_eq!(sent, msg.len() as isize, "send should write all bytes");

    // Receive on the other end
    let mut buf = [0u8; 16];
    let received = unsafe {
        socket_abi::recv(sv[1], buf.as_mut_ptr() as *mut c_void, buf.len(), 0)
    };
    assert_eq!(received, msg.len() as isize, "recv should read all bytes");
    assert_eq!(&buf[..msg.len()], msg);

    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

#[test]
fn socketpair_null_sv_fails() {
    let rc = unsafe {
        socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, std::ptr::null_mut())
    };
    assert_eq!(rc, -1);
}

// ---------------------------------------------------------------------------
// send / recv error paths
// ---------------------------------------------------------------------------

#[test]
fn send_invalid_fd_sets_ebadf_errno() {
    let byte = b'x';
    let rc = unsafe { socket_abi::send(-1, &byte as *const u8 as *const c_void, 1, 0) };
    assert_eq!(rc, -1);

    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

#[test]
fn recv_invalid_fd_sets_ebadf_errno() {
    let mut byte = 0u8;
    let rc = unsafe { socket_abi::recv(-1, &mut byte as *mut u8 as *mut c_void, 1, 0) };
    assert_eq!(rc, -1);

    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

// ---------------------------------------------------------------------------
// shutdown
// ---------------------------------------------------------------------------

#[test]
fn shutdown_invalid_fd_sets_ebadf_errno() {
    let rc = unsafe { socket_abi::shutdown(-1, libc::SHUT_RDWR) };
    assert_eq!(rc, -1);

    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

#[test]
fn shutdown_socketpair() {
    let mut sv = [0 as c_int; 2];
    let rc = unsafe {
        socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr())
    };
    assert_eq!(rc, 0);

    let rc = unsafe { socket_abi::shutdown(sv[0], libc::SHUT_RDWR) };
    assert_eq!(rc, 0, "shutdown on valid socketpair fd should succeed");

    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

// ---------------------------------------------------------------------------
// getsockname
// ---------------------------------------------------------------------------

#[test]
fn getsockname_after_bind() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);

    let rc = unsafe {
        socket_abi::bind(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(rc, 0);

    let mut bound_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    let rc = unsafe {
        socket_abi::getsockname(
            fd,
            &mut bound_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut addrlen,
        )
    };
    assert_eq!(rc, 0, "getsockname should succeed");
    assert_eq!(bound_addr.sin_family, libc::AF_INET as libc::sa_family_t);
    assert_eq!(
        bound_addr.sin_addr.s_addr,
        u32::from_ne_bytes([127, 0, 0, 1])
    );
    // Kernel should have assigned a port
    assert_ne!(bound_addr.sin_port, 0, "kernel should assign a port");

    unsafe { close_fd(fd) };
}

// ---------------------------------------------------------------------------
// setsockopt / getsockopt
// ---------------------------------------------------------------------------

#[test]
fn setsockopt_reuseaddr() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);

    let val: c_int = 1;
    let rc = unsafe {
        socket_abi::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &val as *const c_int as *const c_void,
            std::mem::size_of::<c_int>() as u32,
        )
    };
    assert_eq!(rc, 0, "setsockopt(SO_REUSEADDR) should succeed");

    // Verify with getsockopt
    let mut got_val: c_int = 0;
    let mut optlen = std::mem::size_of::<c_int>() as u32;
    let rc = unsafe {
        socket_abi::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &mut got_val as *mut c_int as *mut c_void,
            &mut optlen,
        )
    };
    assert_eq!(rc, 0, "getsockopt(SO_REUSEADDR) should succeed");
    assert_eq!(got_val, 1, "SO_REUSEADDR should be enabled");

    unsafe { close_fd(fd) };
}

#[test]
fn getsockopt_socket_type() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);

    let mut sock_type: c_int = 0;
    let mut optlen = std::mem::size_of::<c_int>() as u32;
    let rc = unsafe {
        socket_abi::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut sock_type as *mut c_int as *mut c_void,
            &mut optlen,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(sock_type, libc::SOCK_STREAM);

    unsafe { close_fd(fd) };
}

// ---------------------------------------------------------------------------
// sendto / recvfrom via UDP
// ---------------------------------------------------------------------------

#[test]
fn sendto_recvfrom_udp_loopback() {
    // Create two UDP sockets
    let sender = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    let receiver = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(sender >= 0);
    assert!(receiver >= 0);

    // Bind receiver to loopback
    let mut recv_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    recv_addr.sin_family = libc::AF_INET as libc::sa_family_t;
    recv_addr.sin_port = 0;
    recv_addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);

    let rc = unsafe {
        socket_abi::bind(
            receiver,
            &recv_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(rc, 0);

    // Get bound address
    let mut bound: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    unsafe {
        socket_abi::getsockname(
            receiver,
            &mut bound as *mut _ as *mut libc::sockaddr,
            &mut addrlen,
        )
    };

    // Send to receiver
    let msg = b"test";
    let sent = unsafe {
        socket_abi::sendto(
            sender,
            msg.as_ptr() as *const c_void,
            msg.len(),
            0,
            &bound as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(sent, msg.len() as isize);

    // Receive
    let mut buf = [0u8; 32];
    let mut src_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut src_len = std::mem::size_of::<libc::sockaddr_in>() as u32;
    let received = unsafe {
        socket_abi::recvfrom(
            receiver,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            0,
            &mut src_addr as *mut _ as *mut libc::sockaddr,
            &mut src_len,
        )
    };
    assert_eq!(received, msg.len() as isize);
    assert_eq!(&buf[..msg.len()], msg);

    unsafe {
        close_fd(sender);
        close_fd(receiver);
    }
}

// ---------------------------------------------------------------------------
// accept4
// ---------------------------------------------------------------------------

#[test]
fn accept4_invalid_fd_returns_neg1() {
    let rc = unsafe {
        socket_abi::accept4(-1, std::ptr::null_mut(), std::ptr::null_mut(), 0)
    };
    assert_eq!(rc, -1);
}

// ---------------------------------------------------------------------------
// connect + accept end-to-end
// ---------------------------------------------------------------------------

#[test]
fn connect_accept_tcp_loopback() {
    // Create listener
    let listener = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(listener >= 0);

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);

    assert_eq!(
        unsafe {
            socket_abi::bind(
                listener,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        },
        0
    );
    assert_eq!(unsafe { socket_abi::listen(listener, 1) }, 0);

    // Get bound address
    let mut bound: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    unsafe {
        socket_abi::getsockname(
            listener,
            &mut bound as *mut _ as *mut libc::sockaddr,
            &mut addrlen,
        )
    };

    // Connect from client
    let client = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(client >= 0);

    let rc = unsafe {
        socket_abi::connect(
            client,
            &bound as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(rc, 0, "connect to loopback listener should succeed");

    // Accept on server side
    let mut peer_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut peer_len = std::mem::size_of::<libc::sockaddr_in>() as u32;
    let accepted = unsafe {
        socket_abi::accept(
            listener,
            &mut peer_addr as *mut _ as *mut libc::sockaddr,
            &mut peer_len,
        )
    };
    assert!(accepted >= 0, "accept should return valid fd, got {accepted}");

    // Verify we can exchange data
    let msg = b"ping";
    let sent = unsafe { socket_abi::send(client, msg.as_ptr() as *const c_void, msg.len(), 0) };
    assert_eq!(sent, msg.len() as isize);

    let mut buf = [0u8; 16];
    let received = unsafe {
        socket_abi::recv(accepted, buf.as_mut_ptr() as *mut c_void, buf.len(), 0)
    };
    assert_eq!(received, msg.len() as isize);
    assert_eq!(&buf[..msg.len()], msg);

    // Verify getpeername on accepted socket
    let mut name: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    let rc = unsafe {
        socket_abi::getpeername(
            accepted,
            &mut name as *mut _ as *mut libc::sockaddr,
            &mut namelen,
        )
    };
    assert_eq!(rc, 0, "getpeername on accepted socket should succeed");
    assert_eq!(name.sin_family, libc::AF_INET as libc::sa_family_t);

    unsafe {
        close_fd(accepted);
        close_fd(client);
        close_fd(listener);
    }
}
