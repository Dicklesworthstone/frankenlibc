//! ABI layer for `<sys/socket.h>` functions.
//!
//! All socket operations are thin wrappers around `libc` syscalls with
//! membrane validation gating. Input validation (address family, socket
//! type, shutdown mode) delegates to `frankenlibc_core::socket`.

use std::ffi::{c_int, c_void};

use frankenlibc_core::errno;
use frankenlibc_core::socket as socket_core;
use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;

// ---------------------------------------------------------------------------
// socket
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn socket(domain: c_int, sock_type: c_int, protocol: c_int) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Socket, domain as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    // In strict mode, reject unknown address families early.
    // In hardened mode, let the kernel decide (it may support AF values we don't enumerate).
    if !socket_core::valid_address_family(domain) && !mode.heals_enabled() {
        unsafe { set_abi_errno(errno::EAFNOSUPPORT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    if !socket_core::valid_socket_type(sock_type) && !mode.heals_enabled() {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) = match raw_syscall::sys_socket(domain, sock_type, protocol) {
        Ok(fd) => (fd, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// bind
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bind(sockfd: c_int, addr: *const libc::sockaddr, addrlen: u32) -> c_int {
    if sockfd < 0 {
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }

    let (_, decision) = runtime_policy::decide(
        ApiFamily::Socket,
        sockfd as usize,
        addrlen as usize,
        true,
        true,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    if addr.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) = match unsafe { raw_syscall::sys_bind(sockfd, addr as *const u8, addrlen) } {
        Ok(()) => (0, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// listen
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn listen(sockfd: c_int, backlog: c_int) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Socket, sockfd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let effective_backlog = socket_core::valid_backlog(backlog);
    let (rc, adverse) = match raw_syscall::sys_listen(sockfd, effective_backlog) {
        Ok(()) => (0, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 8, adverse);
    rc
}

// ---------------------------------------------------------------------------
// accept
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn accept(
    sockfd: c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut u32,
) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Socket, sockfd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) = match unsafe { raw_syscall::sys_accept(sockfd, addr as *mut u8, addrlen) } {
        Ok(fd) => (fd, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 15, adverse);
    rc
}

// ---------------------------------------------------------------------------
// connect
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn connect(
    sockfd: c_int,
    addr: *const libc::sockaddr,
    addrlen: u32,
) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Socket,
        sockfd as usize,
        addrlen as usize,
        true,
        true,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    if addr.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) =
        match unsafe { raw_syscall::sys_connect(sockfd, addr as *const u8, addrlen) } {
            Ok(()) => (0, false),
            Err(e) => {
                unsafe { set_abi_errno(e) };
                (-1, true)
            }
        };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 15, adverse);
    rc
}

// ---------------------------------------------------------------------------
// send
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn send(
    sockfd: c_int,
    buf: *const c_void,
    len: usize,
    flags: c_int,
) -> isize {
    if sockfd < 0 {
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Socket, sockfd as usize, len, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(
            ApiFamily::Socket,
            decision.profile,
            runtime_policy::scaled_cost(8, len),
            true,
        );
        return -1;
    }

    if buf.is_null() && len > 0 {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) = match unsafe {
        raw_syscall::sys_sendto(sockfd, buf as *const u8, len, flags, std::ptr::null(), 0)
    } {
        Ok(n) => (n, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(
        ApiFamily::Socket,
        decision.profile,
        runtime_policy::scaled_cost(8, len),
        adverse,
    );
    rc
}

// ---------------------------------------------------------------------------
// recv
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn recv(sockfd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize {
    if sockfd < 0 {
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Socket, sockfd as usize, len, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(
            ApiFamily::Socket,
            decision.profile,
            runtime_policy::scaled_cost(8, len),
            true,
        );
        return -1;
    }

    if buf.is_null() && len > 0 {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) = match unsafe {
        raw_syscall::sys_recvfrom(
            sockfd,
            buf as *mut u8,
            len,
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } {
        Ok(n) => (n, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(
        ApiFamily::Socket,
        decision.profile,
        runtime_policy::scaled_cost(8, len),
        adverse,
    );
    rc
}

// ---------------------------------------------------------------------------
// sendto
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sendto(
    sockfd: c_int,
    buf: *const c_void,
    len: usize,
    flags: c_int,
    dest_addr: *const libc::sockaddr,
    addrlen: u32,
) -> isize {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Socket, sockfd as usize, len, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(
            ApiFamily::Socket,
            decision.profile,
            runtime_policy::scaled_cost(8, len),
            true,
        );
        return -1;
    }

    if buf.is_null() && len > 0 {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) = match unsafe {
        raw_syscall::sys_sendto(
            sockfd,
            buf as *const u8,
            len,
            flags,
            dest_addr as *const u8,
            addrlen as usize,
        )
    } {
        Ok(n) => (n, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(
        ApiFamily::Socket,
        decision.profile,
        runtime_policy::scaled_cost(8, len),
        adverse,
    );
    rc
}

// ---------------------------------------------------------------------------
// recvfrom
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn recvfrom(
    sockfd: c_int,
    buf: *mut c_void,
    len: usize,
    flags: c_int,
    src_addr: *mut libc::sockaddr,
    addrlen: *mut u32,
) -> isize {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Socket, sockfd as usize, len, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(
            ApiFamily::Socket,
            decision.profile,
            runtime_policy::scaled_cost(8, len),
            true,
        );
        return -1;
    }

    if buf.is_null() && len > 0 {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) = match unsafe {
        raw_syscall::sys_recvfrom(
            sockfd,
            buf as *mut u8,
            len,
            flags,
            src_addr as *mut u8,
            addrlen,
        )
    } {
        Ok(n) => (n, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(
        ApiFamily::Socket,
        decision.profile,
        runtime_policy::scaled_cost(8, len),
        adverse,
    );
    rc
}

// ---------------------------------------------------------------------------
// shutdown
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shutdown(sockfd: c_int, how: c_int) -> c_int {
    if sockfd < 0 {
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }

    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Socket, sockfd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let effective_how = if !socket_core::valid_shutdown_how(how) {
        if mode.heals_enabled() {
            socket_core::SHUT_RDWR // default to full shutdown in hardened mode
        } else {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
            return -1;
        }
    } else {
        how
    };

    let (rc, adverse) = match raw_syscall::sys_shutdown(sockfd, effective_how) {
        Ok(()) => (0, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 8, adverse);
    rc
}

// ---------------------------------------------------------------------------
// setsockopt
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setsockopt(
    sockfd: c_int,
    level: c_int,
    optname: c_int,
    optval: *const c_void,
    optlen: u32,
) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Socket,
        sockfd as usize,
        optlen as usize,
        true,
        true,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) = match unsafe {
        raw_syscall::sys_setsockopt(sockfd, level, optname, optval as *const u8, optlen as usize)
    } {
        Ok(()) => (0, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// getsockopt
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsockopt(
    sockfd: c_int,
    level: c_int,
    optname: c_int,
    optval: *mut c_void,
    optlen: *mut u32,
) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Socket, sockfd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) = match unsafe {
        raw_syscall::sys_getsockopt(sockfd, level, optname, optval as *mut u8, optlen)
    } {
        Ok(()) => (0, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// getpeername
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpeername(
    sockfd: c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut u32,
) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Socket, sockfd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) =
        match unsafe { raw_syscall::sys_getpeername(sockfd, addr as *mut u8, addrlen) } {
            Ok(()) => (0, false),
            Err(e) => {
                unsafe { set_abi_errno(e) };
                (-1, true)
            }
        };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 8, adverse);
    rc
}

// ---------------------------------------------------------------------------
// getsockname
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsockname(
    sockfd: c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut u32,
) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Socket, sockfd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) =
        match unsafe { raw_syscall::sys_getsockname(sockfd, addr as *mut u8, addrlen) } {
            Ok(()) => (0, false),
            Err(e) => {
                unsafe { set_abi_errno(e) };
                (-1, true)
            }
        };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 8, adverse);
    rc
}

// ---------------------------------------------------------------------------
// socketpair
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn socketpair(
    domain: c_int,
    sock_type: c_int,
    protocol: c_int,
    sv: *mut c_int,
) -> c_int {
    let (mode, decision) = runtime_policy::decide(ApiFamily::Socket, sv as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    if sv.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    if !socket_core::valid_address_family(domain) && !mode.heals_enabled() {
        unsafe { set_abi_errno(errno::EAFNOSUPPORT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    if !socket_core::valid_socket_type(sock_type) && !mode.heals_enabled() {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) =
        match unsafe { raw_syscall::sys_socketpair(domain, sock_type, protocol, sv) } {
            Ok(()) => (0, false),
            Err(e) => {
                unsafe { set_abi_errno(e) };
                (-1, true)
            }
        };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// sendmsg
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sendmsg(sockfd: c_int, msg: *const libc::msghdr, flags: c_int) -> isize {
    let (_, decision) = runtime_policy::decide(ApiFamily::Socket, msg as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    if msg.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) = match unsafe { raw_syscall::sys_sendmsg(sockfd, msg as *const u8, flags) } {
        Ok(n) => (n, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 12, adverse);
    rc
}

// ---------------------------------------------------------------------------
// recvmsg
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn recvmsg(sockfd: c_int, msg: *mut libc::msghdr, flags: c_int) -> isize {
    let (_, decision) = runtime_policy::decide(ApiFamily::Socket, msg as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    if msg.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) = match unsafe { raw_syscall::sys_recvmsg(sockfd, msg as *mut u8, flags) } {
        Ok(n) => (n, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 12, adverse);
    rc
}

// ---------------------------------------------------------------------------
// accept4 (Linux extension)
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn accept4(
    sockfd: c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut u32,
    flags: c_int,
) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Socket, sockfd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let (rc, adverse) =
        match unsafe { raw_syscall::sys_accept4(sockfd, addr as *mut u8, addrlen, flags) } {
            Ok(fd) => (fd, false),
            Err(e) => {
                unsafe { set_abi_errno(e) };
                (-1, true)
            }
        };
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 15, adverse);
    rc
}

// ---------------------------------------------------------------------------
// getpeereid (BSD: peer credentials of a Unix-domain socket)
// ---------------------------------------------------------------------------
//
// On Linux this is a thin wrapper over `getsockopt(s, SOL_SOCKET,
// SO_PEERCRED, ...)`: the kernel returns a `struct ucred { pid, uid,
// gid }` describing the peer of a connected Unix-domain socket and we
// split out the uid/gid fields. Used by sshd, postfix, sudo, and
// other privilege-separating daemons.
//
// Errors propagate from getsockopt — typical failures are ENOTSOCK
// (`s` isn't a socket), ENOTCONN (Unix socket not connected), or
// EBADF/EINVAL.

/// BSD `getpeereid(s, euid, egid)` — fetch the effective uid+gid of
/// the peer connected to Unix-domain socket `s`. Writes the values
/// into `*euid` / `*egid` and returns 0 on success; on failure
/// returns -1 and sets errno per `getsockopt(SO_PEERCRED)`.
///
/// `euid` and `egid` must both be non-NULL writable output pointers.
///
/// # Safety
///
/// Caller must ensure `euid` and `egid`, when non-NULL, point to
/// writable `uid_t` / `gid_t` storage. `s` must be a valid file
/// descriptor (the kernel validates this and returns EBADF if not).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpeereid(
    s: c_int,
    euid: *mut libc::uid_t,
    egid: *mut libc::gid_t,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Socket, s as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let mut cred: libc::ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len: u32 = std::mem::size_of::<libc::ucred>() as u32;
    let (rc, adverse) = match unsafe {
        raw_syscall::sys_getsockopt(
            s,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast::<u8>(),
            &mut len,
        )
    } {
        Ok(()) => (0, false),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            (-1, true)
        }
    };
    if rc != 0 {
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 10, adverse);
        return rc;
    }

    if len < std::mem::size_of::<libc::ucred>() as u32 {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 10, true);
        return -1;
    }

    if euid.is_null() || egid.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    // SAFETY: both output pointers were checked for NULL above; the C caller
    // contract requires writable uid_t/gid_t storage.
    unsafe {
        *euid = cred.uid;
        *egid = cred.gid;
    }
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 10, false);
    0
}

// ---------------------------------------------------------------------------
// glibc reserved-namespace aliases:
// __accept / __bind / __listen / __sendto / __recvfrom /
// __getsockname / __getpeername
// ---------------------------------------------------------------------------

/// glibc reserved-namespace alias for [`accept`].
///
/// # Safety
///
/// Same as [`accept`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __accept(
    sockfd: c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut u32,
) -> c_int {
    unsafe { accept(sockfd, addr, addrlen) }
}

/// glibc reserved-namespace alias for [`bind`].
///
/// # Safety
///
/// Same as [`bind`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __bind(sockfd: c_int, addr: *const libc::sockaddr, addrlen: u32) -> c_int {
    unsafe { bind(sockfd, addr, addrlen) }
}

/// glibc reserved-namespace alias for [`listen`].
///
/// # Safety
///
/// Same as [`listen`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __listen(sockfd: c_int, backlog: c_int) -> c_int {
    unsafe { listen(sockfd, backlog) }
}

/// glibc reserved-namespace alias for [`sendto`].
///
/// # Safety
///
/// Same as [`sendto`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sendto(
    sockfd: c_int,
    buf: *const c_void,
    len: usize,
    flags: c_int,
    dest_addr: *const libc::sockaddr,
    addrlen: u32,
) -> isize {
    unsafe { sendto(sockfd, buf, len, flags, dest_addr, addrlen) }
}

/// glibc reserved-namespace alias for [`recvfrom`].
///
/// # Safety
///
/// Same as [`recvfrom`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __recvfrom(
    sockfd: c_int,
    buf: *mut c_void,
    len: usize,
    flags: c_int,
    src_addr: *mut libc::sockaddr,
    addrlen: *mut u32,
) -> isize {
    unsafe { recvfrom(sockfd, buf, len, flags, src_addr, addrlen) }
}

/// glibc reserved-namespace alias for [`getsockname`].
///
/// # Safety
///
/// Same as [`getsockname`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getsockname(
    sockfd: c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut u32,
) -> c_int {
    unsafe { getsockname(sockfd, addr, addrlen) }
}

/// glibc reserved-namespace alias for [`getpeername`].
///
/// # Safety
///
/// Same as [`getpeername`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getpeername(
    sockfd: c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut u32,
) -> c_int {
    unsafe { getpeername(sockfd, addr, addrlen) }
}

/// glibc reserved-namespace alias for [`socketpair`].
///
/// # Safety
///
/// Same as [`socketpair`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __socketpair(
    domain: c_int,
    sock_type: c_int,
    protocol: c_int,
    sv: *mut c_int,
) -> c_int {
    unsafe { socketpair(domain, sock_type, protocol, sv) }
}

/// glibc reserved-namespace alias for [`sendmsg`].
///
/// # Safety
///
/// Same as [`sendmsg`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sendmsg(sockfd: c_int, msg: *const libc::msghdr, flags: c_int) -> isize {
    unsafe { sendmsg(sockfd, msg, flags) }
}

/// glibc reserved-namespace alias for [`recvmsg`].
///
/// # Safety
///
/// Same as [`recvmsg`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __recvmsg(sockfd: c_int, msg: *mut libc::msghdr, flags: c_int) -> isize {
    unsafe { recvmsg(sockfd, msg, flags) }
}

/// glibc reserved-namespace alias for [`setsockopt`].
///
/// # Safety
///
/// Same as [`setsockopt`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __setsockopt(
    sockfd: c_int,
    level: c_int,
    optname: c_int,
    optval: *const c_void,
    optlen: u32,
) -> c_int {
    unsafe { setsockopt(sockfd, level, optname, optval, optlen) }
}

/// glibc reserved-namespace alias for [`getsockopt`].
///
/// # Safety
///
/// Same as [`getsockopt`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getsockopt(
    sockfd: c_int,
    level: c_int,
    optname: c_int,
    optval: *mut c_void,
    optlen: *mut u32,
) -> c_int {
    unsafe { getsockopt(sockfd, level, optname, optval, optlen) }
}

/// glibc reserved-namespace alias for [`shutdown`].
///
/// # Safety
///
/// Same as [`shutdown`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __shutdown(sockfd: c_int, how: c_int) -> c_int {
    unsafe { shutdown(sockfd, how) }
}
