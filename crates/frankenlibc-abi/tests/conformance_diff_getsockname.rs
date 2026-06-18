#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getsockname/getpeername oracle; one real socket

//! Differential gate for getsockname / getpeername (bd-otjbrp) — no differential
//! gate existed. A single AF_INET socket is created and bound to 127.0.0.1:0 via
//! neutral libc; then BOTH impls query that SAME kernel socket, so the full
//! sockaddr_in (family, port, addr) and addrlen must match exactly. getpeername
//! on the unconnected socket must yield the same ENOTCONN/-1 from both. No mocks.

use std::ffi::c_int;
use std::mem::MaybeUninit;

unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}
fn errno() -> c_int { unsafe { *__errno_location() } }

/// Query a socket via the given getsockname/getpeername-shaped fn; capture
/// (rc, errno, sa_family, port_be, addr_be, addrlen).
fn query(fd: c_int, f: unsafe extern "C" fn(c_int, *mut libc::sockaddr, *mut u32) -> c_int) -> (c_int, c_int, u16, u16, u32, u32) {
    unsafe {
        let mut sa = MaybeUninit::<libc::sockaddr_in>::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as u32;
        *__errno_location() = 0;
        let rc = f(fd, sa.as_mut_ptr() as *mut libc::sockaddr, &mut len);
        let er = errno();
        let s = sa.assume_init();
        (rc, er, s.sin_family, s.sin_port, s.sin_addr.s_addr, len)
    }
}

#[test]
fn getsockname_matches_glibc_same_socket() {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert!(fd >= 0, "socket() failed");
        let sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0, // kernel assigns
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) },
            sin_zero: [0; 8],
        };
        let r = libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32);
        assert_eq!(r, 0, "bind() failed");

        // Both impls query the SAME bound socket -> everything must match.
        let g = query(fd, libc::getsockname);
        let f = query(fd, frankenlibc_abi::socket_abi::getsockname);
        libc::close(fd);
        assert_eq!(f, g, "getsockname same-socket: fl={f:?} glibc={g:?}");
        assert_eq!(g.0, 0, "getsockname rc 0");
        assert_eq!(g.2, libc::AF_INET as u16, "AF_INET");
        assert_eq!(g.4, u32::from_ne_bytes([127, 0, 0, 1]), "127.0.0.1");
        assert!(g.3 != 0, "kernel assigned a nonzero port");
    }
}

#[test]
fn getpeername_unconnected_matches_glibc() {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert!(fd >= 0);
        let g = query(fd, libc::getpeername);
        let f = query(fd, frankenlibc_abi::socket_abi::getpeername);
        libc::close(fd);
        // rc/-1 and errno must match (ENOTCONN on an unconnected socket).
        assert_eq!((f.0, f.1), (g.0, g.1), "getpeername(unconnected): fl=(rc{},errno{}) glibc=(rc{},errno{})", f.0, f.1, g.0, g.1);
        assert_eq!((g.0, g.1), (-1, libc::ENOTCONN), "glibc: -1/ENOTCONN");
    }
}
