//! ABI layer for `<sys/socket.h>` functions.
//!
//! All socket operations are thin wrappers around `libc` syscalls with
//! membrane validation gating. Input validation (address family, socket
//! type, shutdown mode) delegates to `frankenlibc_core::socket`.

use std::ffi::{c_int, c_void};

use frankenlibc_core::errno;
use frankenlibc_core::socket as socket_core;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

#[inline]
fn errno_from_syscall_failure(ret: libc::c_long, default_errno: c_int) -> c_int {
    if let Some(host_errno) = std::io::Error::last_os_error().raw_os_error()
        && host_errno != 0
    {
        return host_errno;
    }

    // Some libc/syscall combinations may surface raw negative errno values
    // without populating host errno. Recover a deterministic errno in that case.
    if ret < 0 {
        let inferred = ret.saturating_neg();
        if (1..=4095).contains(&inferred) {
            return inferred as c_int;
        }
    }

    default_errno
}

#[inline]
unsafe fn syscall_ret_int(ret: libc::c_long) -> c_int {
    if ret < 0 {
        unsafe { set_abi_errno(errno_from_syscall_failure(ret, errno::EINVAL)) };
        -1
    } else {
        ret as c_int
    }
}

#[inline]
unsafe fn syscall_ret_size(ret: libc::c_long) -> isize {
    if ret < 0 {
        unsafe { set_abi_errno(errno_from_syscall_failure(ret, errno::EINVAL)) };
        -1
    } else {
        ret as isize
    }
}

// ---------------------------------------------------------------------------
// socket
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn socket(domain: c_int, sock_type: c_int, protocol: c_int) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Socket, domain as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
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

    let rc =
        unsafe { syscall_ret_int(libc::syscall(libc::SYS_socket, domain, sock_type, protocol)) };
    let adverse = rc < 0;
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
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    if addr.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { syscall_ret_int(libc::syscall(libc::SYS_bind, sockfd, addr, addrlen)) };
    let adverse = rc != 0;
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
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let effective_backlog = socket_core::valid_backlog(backlog);
    let rc = unsafe { syscall_ret_int(libc::syscall(libc::SYS_listen, sockfd, effective_backlog)) };
    let adverse = rc != 0;
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
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { syscall_ret_int(libc::syscall(libc::SYS_accept, sockfd, addr, addrlen)) };
    let adverse = rc < 0;
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
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    if addr.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { syscall_ret_int(libc::syscall(libc::SYS_connect, sockfd, addr, addrlen)) };
    let adverse = rc != 0;
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
        runtime_policy::decide(ApiFamily::Socket, buf as usize, len, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
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

    let rc = unsafe {
        syscall_ret_size(libc::syscall(
            libc::SYS_sendto,
            sockfd,
            buf,
            len,
            flags,
            std::ptr::null::<libc::sockaddr>(),
            0u32,
        ))
    };
    let adverse = rc < 0;
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

    let (_, decision) = runtime_policy::decide(ApiFamily::Socket, buf as usize, len, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
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

    let rc = unsafe {
        syscall_ret_size(libc::syscall(
            libc::SYS_recvfrom,
            sockfd,
            buf,
            len,
            flags,
            std::ptr::null_mut::<libc::sockaddr>(),
            std::ptr::null_mut::<u32>(),
        ))
    };
    let adverse = rc < 0;
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
        runtime_policy::decide(ApiFamily::Socket, buf as usize, len, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
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

    let rc = unsafe {
        syscall_ret_size(libc::syscall(
            libc::SYS_sendto,
            sockfd,
            buf,
            len,
            flags,
            dest_addr,
            addrlen,
        ))
    };
    let adverse = rc < 0;
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
    let (_, decision) = runtime_policy::decide(ApiFamily::Socket, buf as usize, len, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
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

    let rc = unsafe {
        syscall_ret_size(libc::syscall(
            libc::SYS_recvfrom,
            sockfd,
            buf,
            len,
            flags,
            src_addr,
            addrlen,
        ))
    };
    let adverse = rc < 0;
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

    let rc = unsafe { syscall_ret_int(libc::syscall(libc::SYS_shutdown, sockfd, effective_how)) };
    let adverse = rc != 0;
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
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(libc::syscall(
            libc::SYS_setsockopt,
            sockfd,
            level,
            optname,
            optval,
            optlen,
        ))
    };
    let adverse = rc != 0;
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
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(libc::syscall(
            libc::SYS_getsockopt,
            sockfd,
            level,
            optname,
            optval,
            optlen,
        ))
    };
    let adverse = rc != 0;
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
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let rc =
        unsafe { syscall_ret_int(libc::syscall(libc::SYS_getpeername, sockfd, addr, addrlen)) };
    let adverse = rc != 0;
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
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let rc =
        unsafe { syscall_ret_int(libc::syscall(libc::SYS_getsockname, sockfd, addr, addrlen)) };
    let adverse = rc != 0;
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

    let rc = unsafe {
        syscall_ret_int(libc::syscall(
            libc::SYS_socketpair,
            domain,
            sock_type,
            protocol,
            sv,
        ))
    };
    let adverse = rc != 0;
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
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    if msg.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { syscall_ret_size(libc::syscall(libc::SYS_sendmsg, sockfd, msg, flags)) };
    let adverse = rc < 0;
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
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    if msg.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { syscall_ret_size(libc::syscall(libc::SYS_recvmsg, sockfd, msg, flags)) };
    let adverse = rc < 0;
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
        runtime_policy::observe(ApiFamily::Socket, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(libc::syscall(
            libc::SYS_accept4,
            sockfd,
            addr,
            addrlen,
            flags,
        ))
    };
    let adverse = rc < 0;
    runtime_policy::observe(ApiFamily::Socket, decision.profile, 15, adverse);
    rc
}
