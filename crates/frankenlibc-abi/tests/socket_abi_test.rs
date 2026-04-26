//! ABI integration tests for socket_abi native implementations.
//!
//! Covers: socket, bind, listen, connect, send, recv, shutdown,
//! socketpair, getsockname, setsockopt, getsockopt, getpeername,
//! sendto, recvfrom, sendmsg, recvmsg, accept, accept4, getpeereid.

#![allow(unsafe_code)]

use std::ffi::{c_int, c_void};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::socket_abi;
use frankenlibc_core::errno;
use frankenlibc_core::syscall as raw_syscall;

/// Close a file descriptor via the core syscall veneer.
unsafe fn close_fd(fd: c_int) {
    let _ = raw_syscall::sys_close(fd);
}

// ---------------------------------------------------------------------------
// socket creation
// ---------------------------------------------------------------------------

#[test]
fn socket_tcp_creates_valid_fd() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(
        fd >= 0,
        "socket(AF_INET, SOCK_STREAM) should return valid fd, got {fd}"
    );
    unsafe { close_fd(fd) };
}

#[test]
fn socket_udp_creates_valid_fd() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(
        fd >= 0,
        "socket(AF_INET, SOCK_DGRAM) should return valid fd, got {fd}"
    );
    unsafe { close_fd(fd) };
}

#[test]
fn socket_unix_stream() {
    let fd = unsafe { socket_abi::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(
        fd >= 0,
        "socket(AF_UNIX, SOCK_STREAM) should return valid fd"
    );
    unsafe { close_fd(fd) };
}

#[test]
fn socket_cloexec_flag() {
    let fd =
        unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
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
    let rc =
        unsafe { socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
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
    let rc =
        unsafe { socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    assert_eq!(rc, 0);

    // Send data through one end
    let msg = b"hello";
    let sent = unsafe { socket_abi::send(sv[0], msg.as_ptr() as *const c_void, msg.len(), 0) };
    assert_eq!(sent, msg.len() as isize, "send should write all bytes");

    // Receive on the other end
    let mut buf = [0u8; 16];
    let received =
        unsafe { socket_abi::recv(sv[1], buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
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
    let rc =
        unsafe { socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
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
    let rc = unsafe { socket_abi::accept4(-1, std::ptr::null_mut(), std::ptr::null_mut(), 0) };
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
    assert!(
        accepted >= 0,
        "accept should return valid fd, got {accepted}"
    );

    // Verify we can exchange data
    let msg = b"ping";
    let sent = unsafe { socket_abi::send(client, msg.as_ptr() as *const c_void, msg.len(), 0) };
    assert_eq!(sent, msg.len() as isize);

    let mut buf = [0u8; 16];
    let received =
        unsafe { socket_abi::recv(accepted, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
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

// ---------------------------------------------------------------------------
// socket — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn socket_nonblock_flag() {
    let fd =
        unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    assert!(fd >= 0, "SOCK_NONBLOCK should not prevent creation");
    unsafe { close_fd(fd) };
}

#[test]
fn socket_invalid_domain_fails() {
    let fd = unsafe { socket_abi::socket(-1, libc::SOCK_STREAM, 0) };
    assert_eq!(fd, -1, "invalid domain should fail");
}

#[test]
fn socket_unix_dgram() {
    let fd = unsafe { socket_abi::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0, "AF_UNIX SOCK_DGRAM should succeed");
    unsafe { close_fd(fd) };
}

#[test]
fn socket_ipv6_tcp() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "AF_INET6 SOCK_STREAM should succeed");
    unsafe { close_fd(fd) };
}

#[test]
fn socket_ipv6_udp() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0, "AF_INET6 SOCK_DGRAM should succeed");
    unsafe { close_fd(fd) };
}

// ---------------------------------------------------------------------------
// bind — additional
// ---------------------------------------------------------------------------

#[test]
fn bind_ipv6_loopback() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);

    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    addr.sin6_port = 0;
    addr.sin6_addr = libc::in6_addr {
        s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    };

    let rc = unsafe {
        socket_abi::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as u32,
        )
    };
    assert_eq!(rc, 0, "bind to IPv6 loopback should succeed");
    unsafe { close_fd(fd) };
}

// ---------------------------------------------------------------------------
// connect — error path
// ---------------------------------------------------------------------------

#[test]
fn connect_invalid_fd_fails() {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = u16::to_be(1);
    addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);

    let rc = unsafe {
        socket_abi::connect(
            -1,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(rc, -1);
    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

// ---------------------------------------------------------------------------
// accept — error path
// ---------------------------------------------------------------------------

#[test]
fn accept_invalid_fd_fails() {
    let rc = unsafe { socket_abi::accept(-1, std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rc, -1);
    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

// ---------------------------------------------------------------------------
// accept4 — additional
// ---------------------------------------------------------------------------

#[test]
fn accept4_cloexec_flag() {
    let listener = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(listener >= 0);

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);

    unsafe {
        socket_abi::bind(
            listener,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        socket_abi::listen(listener, 1);
    }

    let mut bound: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    unsafe {
        socket_abi::getsockname(
            listener,
            &mut bound as *mut _ as *mut libc::sockaddr,
            &mut addrlen,
        );
    }

    let client = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(client >= 0);
    unsafe {
        socket_abi::connect(
            client,
            &bound as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
    }

    let accepted = unsafe {
        socket_abi::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    assert!(accepted >= 0, "accept4 with SOCK_CLOEXEC should succeed");

    unsafe {
        close_fd(accepted);
        close_fd(client);
        close_fd(listener);
    }
}

// ---------------------------------------------------------------------------
// getpeername — error path
// ---------------------------------------------------------------------------

#[test]
fn getpeername_unconnected_fails() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    let rc = unsafe {
        socket_abi::getpeername(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut addrlen)
    };
    assert_eq!(rc, -1, "getpeername on unconnected socket should fail");

    unsafe { close_fd(fd) };
}

// ---------------------------------------------------------------------------
// shutdown — additional
// ---------------------------------------------------------------------------

#[test]
fn shutdown_read_then_write() {
    let mut sv = [0 as c_int; 2];
    unsafe { socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };

    // Shutdown read side of sv[0]
    let rc = unsafe { socket_abi::shutdown(sv[0], libc::SHUT_RD) };
    assert_eq!(rc, 0, "SHUT_RD should succeed");

    // Shutdown write side of sv[0]
    let rc = unsafe { socket_abi::shutdown(sv[0], libc::SHUT_WR) };
    assert_eq!(rc, 0, "SHUT_WR should succeed");

    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

// ---------------------------------------------------------------------------
// send / recv — additional
// ---------------------------------------------------------------------------

#[test]
fn send_recv_msg_dontwait() {
    let mut sv = [0 as c_int; 2];
    unsafe { socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };

    let msg = b"nowait";
    let sent = unsafe {
        socket_abi::send(
            sv[0],
            msg.as_ptr() as *const c_void,
            msg.len(),
            libc::MSG_DONTWAIT,
        )
    };
    assert_eq!(sent, msg.len() as isize);

    let mut buf = [0u8; 16];
    let received = unsafe {
        socket_abi::recv(
            sv[1],
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    assert_eq!(received, msg.len() as isize);
    assert_eq!(&buf[..msg.len()], msg);

    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

#[test]
fn recv_nonblock_empty_returns_eagain() {
    let mut sv = [0 as c_int; 2];
    unsafe {
        socket_abi::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK,
            0,
            sv.as_mut_ptr(),
        )
    };

    let mut buf = [0u8; 16];
    let rc = unsafe { socket_abi::recv(sv[1], buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
    assert_eq!(rc, -1, "recv on empty nonblock socket should fail");
    let err = unsafe { *__errno_location() };
    assert!(
        err == libc::EAGAIN || err == libc::EWOULDBLOCK,
        "expected EAGAIN/EWOULDBLOCK, got {err}"
    );

    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

// ---------------------------------------------------------------------------
// sendto / recvfrom — additional
// ---------------------------------------------------------------------------

#[test]
fn recvfrom_null_addr() {
    // recvfrom with null src_addr is valid — just doesn't fill the source address
    let mut sv = [0 as c_int; 2];
    unsafe { socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) };

    let msg = b"hi";
    unsafe {
        socket_abi::sendto(
            sv[0],
            msg.as_ptr() as *const c_void,
            msg.len(),
            0,
            std::ptr::null(),
            0,
        )
    };

    let mut buf = [0u8; 16];
    let received = unsafe {
        socket_abi::recvfrom(
            sv[1],
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(received, msg.len() as isize);
    assert_eq!(&buf[..msg.len()], msg);

    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

// ---------------------------------------------------------------------------
// sendmsg / recvmsg
// ---------------------------------------------------------------------------

#[test]
fn sendmsg_recvmsg_basic() {
    let mut sv = [0 as c_int; 2];
    unsafe { socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };

    let msg_data = b"msghdr";
    let mut iov = libc::iovec {
        iov_base: msg_data.as_ptr() as *mut c_void,
        iov_len: msg_data.len(),
    };
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;

    let sent = unsafe { socket_abi::sendmsg(sv[0], &hdr, 0) };
    assert_eq!(
        sent,
        msg_data.len() as isize,
        "sendmsg should send all bytes"
    );

    // Receive
    let mut recv_buf = [0u8; 32];
    let mut recv_iov = libc::iovec {
        iov_base: recv_buf.as_mut_ptr() as *mut c_void,
        iov_len: recv_buf.len(),
    };
    let mut recv_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    recv_hdr.msg_iov = &mut recv_iov;
    recv_hdr.msg_iovlen = 1;

    let received = unsafe { socket_abi::recvmsg(sv[1], &mut recv_hdr, 0) };
    assert_eq!(
        received,
        msg_data.len() as isize,
        "recvmsg should receive all bytes"
    );
    assert_eq!(&recv_buf[..msg_data.len()], msg_data);

    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

#[test]
fn sendmsg_invalid_fd_fails() {
    let msg_data = b"x";
    let mut iov = libc::iovec {
        iov_base: msg_data.as_ptr() as *mut c_void,
        iov_len: msg_data.len(),
    };
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;

    let rc = unsafe { socket_abi::sendmsg(-1, &hdr, 0) };
    assert_eq!(rc, -1);
    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

#[test]
fn recvmsg_invalid_fd_fails() {
    let mut buf = [0u8; 16];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut c_void,
        iov_len: buf.len(),
    };
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;

    let rc = unsafe { socket_abi::recvmsg(-1, &mut hdr, 0) };
    assert_eq!(rc, -1);
    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

#[test]
fn sendmsg_scatter_gather() {
    let mut sv = [0 as c_int; 2];
    unsafe { socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };

    // Scatter: send two separate buffers as one message
    let part1 = b"hello";
    let part2 = b" world";
    let mut iovs = [
        libc::iovec {
            iov_base: part1.as_ptr() as *mut c_void,
            iov_len: part1.len(),
        },
        libc::iovec {
            iov_base: part2.as_ptr() as *mut c_void,
            iov_len: part2.len(),
        },
    ];
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_iov = iovs.as_mut_ptr();
    hdr.msg_iovlen = 2;

    let sent = unsafe { socket_abi::sendmsg(sv[0], &hdr, 0) };
    assert_eq!(sent, 11, "sendmsg should send all 11 bytes across 2 iovecs");

    // Gather: receive into one buffer
    let mut recv_buf = [0u8; 32];
    let mut recv_iov = libc::iovec {
        iov_base: recv_buf.as_mut_ptr() as *mut c_void,
        iov_len: recv_buf.len(),
    };
    let mut recv_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    recv_hdr.msg_iov = &mut recv_iov;
    recv_hdr.msg_iovlen = 1;

    let received = unsafe { socket_abi::recvmsg(sv[1], &mut recv_hdr, 0) };
    assert_eq!(received, 11);
    assert_eq!(&recv_buf[..11], b"hello world");

    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

// ---------------------------------------------------------------------------
// setsockopt / getsockopt — additional
// ---------------------------------------------------------------------------

#[test]
fn setsockopt_keepalive() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);

    let val: c_int = 1;
    let rc = unsafe {
        socket_abi::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &val as *const c_int as *const c_void,
            std::mem::size_of::<c_int>() as u32,
        )
    };
    assert_eq!(rc, 0, "setsockopt(SO_KEEPALIVE) should succeed");

    let mut got_val: c_int = 0;
    let mut optlen = std::mem::size_of::<c_int>() as u32;
    let rc = unsafe {
        socket_abi::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &mut got_val as *mut c_int as *mut c_void,
            &mut optlen,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(got_val, 1, "SO_KEEPALIVE should be enabled");

    unsafe { close_fd(fd) };
}

#[test]
fn getsockopt_sndbuf() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);

    let mut buf_size: c_int = 0;
    let mut optlen = std::mem::size_of::<c_int>() as u32;
    let rc = unsafe {
        socket_abi::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &mut buf_size as *mut c_int as *mut c_void,
            &mut optlen,
        )
    };
    assert_eq!(rc, 0);
    assert!(buf_size > 0, "SO_SNDBUF should be positive, got {buf_size}");

    unsafe { close_fd(fd) };
}

#[test]
fn setsockopt_invalid_fd_fails() {
    let val: c_int = 1;
    let rc = unsafe {
        socket_abi::setsockopt(
            -1,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &val as *const c_int as *const c_void,
            std::mem::size_of::<c_int>() as u32,
        )
    };
    assert_eq!(rc, -1);
    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

// ---------------------------------------------------------------------------
// getsockname — additional
// ---------------------------------------------------------------------------

#[test]
fn getsockname_invalid_fd_fails() {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    let rc = unsafe {
        socket_abi::getsockname(-1, &mut addr as *mut _ as *mut libc::sockaddr, &mut addrlen)
    };
    assert_eq!(rc, -1);
    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

// ---------------------------------------------------------------------------
// listen — error path
// ---------------------------------------------------------------------------

#[test]
fn listen_without_bind_fails() {
    let fd = unsafe { socket_abi::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0);

    // listen on a UDP socket should fail (EOPNOTSUPP)
    let rc = unsafe { socket_abi::listen(fd, 5) };
    assert_eq!(rc, -1, "listen on UDP socket should fail");

    unsafe { close_fd(fd) };
}

// ---------------------------------------------------------------------------
// socketpair — additional
// ---------------------------------------------------------------------------

#[test]
fn socketpair_dgram() {
    let mut sv = [0 as c_int; 2];
    let rc = unsafe { socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair(AF_UNIX, SOCK_DGRAM) should succeed");
    assert!(sv[0] >= 0 && sv[1] >= 0);
    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

#[test]
fn socketpair_nonblock() {
    let mut sv = [0 as c_int; 2];
    let rc = unsafe {
        socket_abi::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK,
            0,
            sv.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 0, "socketpair with SOCK_NONBLOCK should succeed");

    // Read on empty nonblock socket should fail with EAGAIN
    let mut buf = [0u8; 1];
    let rc = unsafe { socket_abi::recv(sv[0], buf.as_mut_ptr() as *mut c_void, 1, 0) };
    assert_eq!(rc, -1);
    let err = unsafe { *__errno_location() };
    assert!(err == libc::EAGAIN || err == libc::EWOULDBLOCK);

    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

// ---------------------------------------------------------------------------
// getpeereid (BSD: peer credentials of a Unix-domain socket)
// ---------------------------------------------------------------------------

#[test]
fn getpeereid_returns_self_credentials_on_socketpair() {
    let mut sv = [0i32; 2];
    let rc =
        unsafe { socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair failed");

    let my_uid = unsafe { libc::geteuid() };
    let my_gid = unsafe { libc::getegid() };

    let mut peer_uid: libc::uid_t = u32::MAX;
    let mut peer_gid: libc::gid_t = u32::MAX;
    let rc = unsafe { socket_abi::getpeereid(sv[0], &mut peer_uid, &mut peer_gid) };
    assert_eq!(rc, 0, "getpeereid failed; errno={}", unsafe {
        *__errno_location()
    });
    assert_eq!(
        peer_uid, my_uid,
        "peer uid must match our own on socketpair"
    );
    assert_eq!(
        peer_gid, my_gid,
        "peer gid must match our own on socketpair"
    );

    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

#[test]
fn getpeereid_null_outputs_return_efault() {
    let mut sv = [0i32; 2];
    let rc =
        unsafe { socket_abi::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    assert_eq!(rc, 0);

    unsafe { *__errno_location() = 0 };
    let rc = unsafe { socket_abi::getpeereid(sv[0], std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rc, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe { *__errno_location() = 0 };
    let mut peer_uid: libc::uid_t = u32::MAX;
    let rc = unsafe { socket_abi::getpeereid(sv[0], &mut peer_uid, std::ptr::null_mut()) };
    assert_eq!(rc, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);
    assert_eq!(peer_uid, u32::MAX);

    unsafe {
        close_fd(sv[0]);
        close_fd(sv[1]);
    }
}

#[test]
fn getpeereid_returns_minus_one_for_bad_fd() {
    unsafe { *__errno_location() = 0 };
    let mut peer_uid: libc::uid_t = 0;
    let mut peer_gid: libc::gid_t = 0;
    let rc = unsafe { socket_abi::getpeereid(-1, &mut peer_uid, &mut peer_gid) };
    assert_eq!(rc, -1, "bad fd must yield -1");
    let err = unsafe { *__errno_location() };
    assert_eq!(err, libc::EBADF, "errno must be EBADF for fd = -1");
}

#[test]
fn getpeereid_on_non_socket_fd_yields_error() {
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0);
    unsafe { *__errno_location() = 0 };
    let mut peer_uid: libc::uid_t = 0;
    let mut peer_gid: libc::gid_t = 0;
    let rc = unsafe { socket_abi::getpeereid(fd, &mut peer_uid, &mut peer_gid) };
    assert_eq!(rc, -1);
    let err = unsafe { *__errno_location() };
    assert_eq!(err, libc::ENOTSOCK);
    unsafe { close_fd(fd) };
}

// ---------------------------------------------------------------------------
// glibc reserved-namespace aliases:
// __accept / __bind / __listen / __sendto / __recvfrom /
// __getsockname / __getpeername
// ---------------------------------------------------------------------------

#[test]
fn under_socket_aliases_round_trip_via_socketpair() {
    // socketpair() gives us a connected pair we can run all 7
    // alias entry points against without depending on the network.
    let mut pair = [-1 as c_int; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
    assert_eq!(rc, 0);
    let (a, b) = (pair[0], pair[1]);

    // __sendto / __recvfrom: zero-length flags (no flags), no peer
    // address (NULL/0 for AF_UNIX socketpair).
    let payload: &[u8] = b"alias-test";
    let n_sent = unsafe {
        socket_abi::__sendto(
            a,
            payload.as_ptr() as *const c_void,
            payload.len(),
            0,
            std::ptr::null(),
            0,
        )
    };
    assert_eq!(n_sent as usize, payload.len());

    let mut buf = [0u8; 32];
    let n_recv = unsafe {
        socket_abi::__recvfrom(
            b,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(n_recv as usize, payload.len());
    assert_eq!(&buf[..payload.len()], payload);

    // __getsockname / __getpeername on a unix socketpair return
    // success even though the address is unnamed.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut len: u32 = std::mem::size_of::<libc::sockaddr_un>() as u32;
    let rc = unsafe {
        socket_abi::__getsockname(a, &mut addr as *mut _ as *mut libc::sockaddr, &mut len)
    };
    assert_eq!(rc, 0);

    let mut peer_addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut peer_len: u32 = std::mem::size_of::<libc::sockaddr_un>() as u32;
    let rc = unsafe {
        socket_abi::__getpeername(
            a,
            &mut peer_addr as *mut _ as *mut libc::sockaddr,
            &mut peer_len,
        )
    };
    assert_eq!(rc, 0);

    unsafe { close_fd(a) };
    unsafe { close_fd(b) };
}

#[test]
fn under_bind_listen_accept_aliases_via_unix_listener() {
    // Build a temporary AF_UNIX listener path so we can exercise
    // __bind/__listen and (lightly) verify __accept signatures
    // resolve. We don't actually accept here — the goal is the
    // bind/listen sequence on a fresh socket.
    let path = format!(
        "/tmp/franken_under_socket_alias_{}.sock",
        std::process::id()
    );
    let _ = std::fs::remove_file(&path);
    let path_c = std::ffi::CString::new(path.clone()).unwrap();

    let listener = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(listener >= 0);

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;
    let bytes = path_c.as_bytes();
    assert!(bytes.len() < addr.sun_path.len());
    for (i, &b) in bytes.iter().enumerate() {
        addr.sun_path[i] = b as i8;
    }
    let addrlen = (std::mem::size_of::<u16>() + bytes.len() + 1) as u32;

    let rc = unsafe {
        socket_abi::__bind(
            listener,
            &addr as *const _ as *const libc::sockaddr,
            addrlen,
        )
    };
    assert_eq!(rc, 0, "__bind should succeed");

    let rc = unsafe { socket_abi::__listen(listener, 1) };
    assert_eq!(rc, 0, "__listen should succeed");

    unsafe { close_fd(listener) };
    let _ = std::fs::remove_file(&path);
}
