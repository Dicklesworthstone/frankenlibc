//! Differential gate: AF-independent multicast source filters (setsourcefilter /
//! getsourcefilter) vs live host glibc.
//!
//! fl previously passed MCAST_MSFILTER at SOL_SOCKET, but that option lives at
//! the protocol level (SOL_IP / SOL_IPV6 / ...), selected from the group family
//! and grouplen exactly like glibc's __get_sol. The bug is observable in errno:
//! the wrong level yields ENOPROTOOPT (92) where glibc returns EINVAL (22). We
//! compare both rc AND errno — read from fl's own errno slot vs the host's —
//! since rc alone (both fail here) would not distinguish the levels.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::{errno_abi, glibc_internal_abi as fl};
use std::ffi::{c_int, c_uint, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
    fn socket(domain: c_int, ty: c_int, proto: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
}
type SetFn = unsafe extern "C" fn(
    c_int,
    c_uint,
    *const c_void,
    c_uint,
    c_uint,
    c_uint,
    *const c_void,
) -> c_int;

fn glibc_set() -> SetFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        std::mem::transmute(dlsym(h, c"setsourcefilter".as_ptr()))
    }
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const MCAST_INCLUDE: c_uint = 1;
const SS_SIZE: usize = std::mem::size_of::<libc::sockaddr_storage>();

fn sockaddr_in(addr_be: [u8; 4]) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
    b[4..8].copy_from_slice(&addr_be);
    b
}
fn sockaddr_in6(addr: [u8; 16]) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
    b[8..24].copy_from_slice(&addr);
    b
}

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

/// Call glibc setsourcefilter, returning (rc, errno-on-failure).
fn call_glibc(set: SetFn, fd: c_int, group: &[u8], srcs: &[u8], numsrc: c_uint) -> (c_int, c_int) {
    unsafe {
        *libc::__errno_location() = 0;
        let rc = set(
            fd,
            0,
            group.as_ptr().cast(),
            group.len() as c_uint,
            MCAST_INCLUDE,
            numsrc,
            srcs.as_ptr().cast(),
        );
        (rc, if rc < 0 { host_errno() } else { 0 })
    }
}
/// Call fl setsourcefilter, returning (rc, fl-errno-on-failure).
fn call_fl(fd: c_int, group: &[u8], srcs: &[u8], numsrc: c_uint) -> (c_int, c_int) {
    unsafe {
        errno_abi::set_abi_errno(0);
        let rc = fl::setsourcefilter(
            fd,
            0,
            group.as_ptr().cast(),
            group.len() as c_uint,
            MCAST_INCLUDE,
            numsrc,
            srcs.as_ptr().cast(),
        );
        (
            rc,
            if rc < 0 {
                *errno_abi::__errno_location()
            } else {
                0
            },
        )
    }
}

#[test]
fn bad_grouplen_einval_on_both() {
    let gset = glibc_set();
    let group = sockaddr_in([224, 0, 0, 1]);
    // grouplen matching no sol_map struct size (16/20/28): both reject with the
    // SAME errno (EINVAL) — the wrong-level bug would surface a different errno.
    for &glen in &[0u32, 8, 10, 12, 17, 24, 100] {
        let mut grp = vec![0u8; glen.max(2) as usize];
        if grp.len() >= 16 {
            grp[..16].copy_from_slice(&group);
        } else if grp.len() >= 2 {
            grp[..2].copy_from_slice(&AF_INET.to_ne_bytes());
        }
        let g = call_glibc(gset, -1, &grp, &[], 0);
        let f = call_fl(-1, &grp, &[], 0);
        assert_eq!(g, f, "bad grouplen={glen}: glibc(rc,errno)={g:?} fl={f:?}");
        assert_eq!(g.0, -1);
    }
}

fn run_pair(domain: c_int, group: &[u8], src_ss: &[u8]) -> ((c_int, c_int), (c_int, c_int)) {
    unsafe {
        let gfd = socket(domain, libc::SOCK_DGRAM, 0);
        let ffd = socket(domain, libc::SOCK_DGRAM, 0);
        assert!(gfd >= 0 && ffd >= 0, "socket() failed");
        let g = call_glibc(glibc_set(), gfd, group, src_ss, 1);
        let f = call_fl(ffd, group, src_ss, 1);
        close(gfd);
        close(ffd);
        (g, f)
    }
}

#[test]
fn inet_level_parity() {
    let group = sockaddr_in([224, 0, 0, 1]);
    let mut src = [0u8; SS_SIZE];
    src[..16].copy_from_slice(&sockaddr_in([1, 2, 3, 4]));
    let (g, f) = run_pair(libc::AF_INET, &group, &src);
    // Same protocol level → identical (rc, errno) on fl and glibc. The old
    // SOL_SOCKET path returned ENOPROTOOPT (92) where glibc returns EINVAL (22).
    assert_eq!(
        g, f,
        "INET setsourcefilter (rc,errno): glibc={g:?} fl={f:?}"
    );
}

#[test]
fn inet6_level_parity() {
    let mut ga = [0u8; 16];
    ga[0] = 0xff;
    ga[1] = 0x02;
    ga[15] = 0x01;
    let group = sockaddr_in6(ga);
    let mut src = [0u8; SS_SIZE];
    src[..28].copy_from_slice(&sockaddr_in6([0u8; 16]));
    let (g, f) = run_pair(libc::AF_INET6, &group, &src);
    assert_eq!(
        g, f,
        "INET6 setsourcefilter (rc,errno): glibc={g:?} fl={f:?}"
    );
}
