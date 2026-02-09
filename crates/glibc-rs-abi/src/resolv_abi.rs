//! ABI layer for selected resolver functions (`<netdb.h>`).
//!
//! Bootstrap scope:
//! - `getaddrinfo` (numeric host/service support with strict/hardened runtime policy)
//! - `freeaddrinfo`
//! - `getnameinfo` (numeric formatting)
//! - `gai_strerror`

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::int_plus_one)]

use std::ffi::{CStr, c_char, c_int};
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

use glibc_rs_membrane::heal::{HealingAction, global_healing_policy};
use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
fn repair_enabled(mode_heals: bool, action: MembraneAction) -> bool {
    mode_heals || matches!(action, MembraneAction::Repair(_))
}

unsafe fn opt_cstr<'a>(ptr: *const c_char) -> Option<&'a CStr> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller-provided C string pointer.
    Some(unsafe { CStr::from_ptr(ptr) })
}

fn parse_port(service: Option<&CStr>, repair: bool) -> Result<u16, c_int> {
    let Some(service) = service else {
        return Ok(0);
    };
    let text = match service.to_str() {
        Ok(t) => t,
        Err(_) => {
            return if repair {
                Ok(0)
            } else {
                Err(libc::EAI_SERVICE)
            };
        }
    };
    match text.parse::<u16>() {
        Ok(port) => Ok(port),
        Err(_) => {
            if repair {
                global_healing_policy().record(&HealingAction::ReturnSafeDefault);
                Ok(0)
            } else {
                Err(libc::EAI_SERVICE)
            }
        }
    }
}

unsafe fn build_addrinfo_v4(
    ip: Ipv4Addr,
    port: u16,
    hints: Option<&libc::addrinfo>,
) -> *mut libc::addrinfo {
    let (flags, socktype, protocol) = hints
        .map(|h| (h.ai_flags, h.ai_socktype, h.ai_protocol))
        .unwrap_or((0, 0, 0));

    let sockaddr = Box::new(libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()).to_be(),
        },
        sin_zero: [0; 8],
    });
    let sockaddr_ptr = Box::into_raw(sockaddr).cast::<libc::sockaddr>();

    let ai = Box::new(libc::addrinfo {
        ai_flags: flags,
        ai_family: libc::AF_INET,
        ai_socktype: socktype,
        ai_protocol: protocol,
        ai_addrlen: size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ai_addr: sockaddr_ptr,
        ai_canonname: ptr::null_mut(),
        ai_next: ptr::null_mut(),
    });
    Box::into_raw(ai)
}

unsafe fn build_addrinfo_v6(
    ip: Ipv6Addr,
    port: u16,
    hints: Option<&libc::addrinfo>,
) -> *mut libc::addrinfo {
    let (flags, socktype, protocol) = hints
        .map(|h| (h.ai_flags, h.ai_socktype, h.ai_protocol))
        .unwrap_or((0, 0, 0));

    let sockaddr = Box::new(libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as u16,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: ip.octets(),
        },
        sin6_scope_id: 0,
    });
    let sockaddr_ptr = Box::into_raw(sockaddr).cast::<libc::sockaddr>();

    let ai = Box::new(libc::addrinfo {
        ai_flags: flags,
        ai_family: libc::AF_INET6,
        ai_socktype: socktype,
        ai_protocol: protocol,
        ai_addrlen: size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        ai_addr: sockaddr_ptr,
        ai_canonname: ptr::null_mut(),
        ai_next: ptr::null_mut(),
    });
    Box::into_raw(ai)
}

unsafe fn write_c_buffer(
    out: *mut c_char,
    out_len: libc::socklen_t,
    text: &str,
    repair: bool,
) -> Result<bool, c_int> {
    if out.is_null() || out_len == 0 {
        return Ok(false);
    }
    let capacity = out_len as usize;
    let bytes = text.as_bytes();

    if bytes.len() + 1 <= capacity {
        // SAFETY: output buffer capacity is validated above.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), out, bytes.len());
            *out.add(bytes.len()) = 0;
        }
        return Ok(false);
    }

    if !repair {
        return Err(libc::EAI_OVERFLOW);
    }

    let copy_len = capacity.saturating_sub(1);
    if copy_len > 0 {
        // SAFETY: output buffer capacity is validated above.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), out, copy_len) };
    }
    // SAFETY: output buffer has at least one byte because out_len > 0.
    unsafe { *out.add(copy_len) = 0 };
    global_healing_policy().record(&HealingAction::TruncateWithNull {
        requested: bytes.len() + 1,
        truncated: copy_len,
    });
    Ok(true)
}

/// POSIX `getaddrinfo` (numeric address bootstrap implementation).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> c_int {
    if res.is_null() {
        return libc::EAI_FAIL;
    }
    // SAFETY: output pointer is non-null and writable by contract.
    unsafe { *res = ptr::null_mut() };

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Resolver,
        node as usize,
        0,
        true,
        node.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, true);
        return libc::EAI_FAIL;
    }
    let repair = repair_enabled(mode.heals_enabled(), decision.action);

    // SAFETY: optional C-string arguments follow getaddrinfo contract.
    let node_cstr = unsafe { opt_cstr(node) };
    // SAFETY: optional C-string arguments follow getaddrinfo contract.
    let service_cstr = unsafe { opt_cstr(service) };
    let hints_ref = if hints.is_null() {
        None
    } else {
        // SAFETY: hints pointer is caller-provided.
        Some(unsafe { &*hints })
    };

    let port = match parse_port(service_cstr, repair) {
        Ok(port) => port,
        Err(err) => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, true);
            return err;
        }
    };

    let family = hints_ref.map(|h| h.ai_family).unwrap_or(libc::AF_UNSPEC);
    let host_text = node_cstr.and_then(|c| c.to_str().ok());

    let ai_ptr = match host_text {
        Some(text) => {
            if let Ok(v4) = text.parse::<Ipv4Addr>() {
                // SAFETY: allocation helper returns ownership pointer.
                unsafe { build_addrinfo_v4(v4, port, hints_ref) }
            } else if let Ok(v6) = text.parse::<Ipv6Addr>() {
                // SAFETY: allocation helper returns ownership pointer.
                unsafe { build_addrinfo_v6(v6, port, hints_ref) }
            } else if repair {
                global_healing_policy().record(&HealingAction::ReturnSafeDefault);
                // SAFETY: allocation helper returns ownership pointer.
                unsafe { build_addrinfo_v4(Ipv4Addr::LOCALHOST, port, hints_ref) }
            } else {
                runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, true);
                return libc::EAI_NONAME;
            }
        }
        None => match family {
            libc::AF_INET6 => {
                // SAFETY: allocation helper returns ownership pointer.
                unsafe { build_addrinfo_v6(Ipv6Addr::UNSPECIFIED, port, hints_ref) }
            }
            _ => {
                // SAFETY: allocation helper returns ownership pointer.
                unsafe { build_addrinfo_v4(Ipv4Addr::UNSPECIFIED, port, hints_ref) }
            }
        },
    };

    // SAFETY: output pointer is non-null and writable.
    unsafe { *res = ai_ptr };
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, false);
    0
}

/// POSIX `freeaddrinfo`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeaddrinfo(mut res: *mut libc::addrinfo) {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Resolver, res as usize, 0, true, false, 0);
    while !res.is_null() {
        // SAFETY: traversing list allocated by getaddrinfo-compatible producer.
        let next = unsafe { (*res).ai_next };
        // SAFETY: res is valid for read.
        let family = unsafe { (*res).ai_family };
        // SAFETY: res is valid for read.
        let addr_ptr = unsafe { (*res).ai_addr };
        if !addr_ptr.is_null() {
            // SAFETY: ai_addr was allocated as sockaddr_in/sockaddr_in6 by this module.
            unsafe {
                match family {
                    libc::AF_INET => {
                        drop(Box::from_raw(addr_ptr.cast::<libc::sockaddr_in>()));
                    }
                    libc::AF_INET6 => {
                        drop(Box::from_raw(addr_ptr.cast::<libc::sockaddr_in6>()));
                    }
                    _ => {}
                }
            }
        }
        // SAFETY: ai_canonname allocation (if present) is owned by this node.
        let canon = unsafe { (*res).ai_canonname };
        if !canon.is_null() {
            // SAFETY: canonname pointers are owned allocations.
            unsafe { drop(std::ffi::CString::from_raw(canon)) };
        }
        // SAFETY: node ownership belongs to caller of freeaddrinfo.
        unsafe { drop(Box::from_raw(res)) };
        res = next;
    }
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 12, false);
}

/// POSIX `getnameinfo` (numeric bootstrap implementation).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getnameinfo(
    sa: *const libc::sockaddr,
    salen: libc::socklen_t,
    host: *mut c_char,
    hostlen: libc::socklen_t,
    serv: *mut c_char,
    servlen: libc::socklen_t,
    _flags: c_int,
) -> c_int {
    if sa.is_null() {
        return libc::EAI_FAIL;
    }
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Resolver,
        sa as usize,
        (hostlen as usize).saturating_add(servlen as usize),
        true,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 20, true);
        return libc::EAI_FAIL;
    }
    let repair = repair_enabled(mode.heals_enabled(), decision.action);

    // SAFETY: caller provides valid sockaddr for given salen.
    let family = unsafe { (*sa).sa_family as c_int };
    let (host_text, serv_text) = match family {
        libc::AF_INET => {
            if (salen as usize) < size_of::<libc::sockaddr_in>() {
                runtime_policy::observe(ApiFamily::Resolver, decision.profile, 20, true);
                return libc::EAI_FAIL;
            }
            // SAFETY: size checked above.
            let sin = unsafe { &*sa.cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            (ip.to_string(), port.to_string())
        }
        libc::AF_INET6 => {
            if (salen as usize) < size_of::<libc::sockaddr_in6>() {
                runtime_policy::observe(ApiFamily::Resolver, decision.profile, 20, true);
                return libc::EAI_FAIL;
            }
            // SAFETY: size checked above.
            let sin6 = unsafe { &*sa.cast::<libc::sockaddr_in6>() };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            (ip.to_string(), port.to_string())
        }
        _ => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 20, true);
            return libc::EAI_FAMILY;
        }
    };

    // SAFETY: output buffers are caller-provided according to getnameinfo contract.
    let host_truncated = unsafe {
        match write_c_buffer(host, hostlen, &host_text, repair) {
            Ok(truncated) => truncated,
            Err(err) => {
                runtime_policy::observe(ApiFamily::Resolver, decision.profile, 20, true);
                return err;
            }
        }
    };
    // SAFETY: output buffers are caller-provided according to getnameinfo contract.
    let serv_truncated = unsafe {
        match write_c_buffer(serv, servlen, &serv_text, repair) {
            Ok(truncated) => truncated,
            Err(err) => {
                runtime_policy::observe(ApiFamily::Resolver, decision.profile, 20, true);
                return err;
            }
        }
    };

    runtime_policy::observe(
        ApiFamily::Resolver,
        decision.profile,
        20,
        host_truncated || serv_truncated,
    );
    0
}

/// POSIX `gai_strerror`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gai_strerror(errcode: c_int) -> *const c_char {
    match errcode {
        0 => c"Success".as_ptr(),
        libc::EAI_AGAIN => c"Temporary failure in name resolution".as_ptr(),
        libc::EAI_BADFLAGS => c"Invalid value for ai_flags".as_ptr(),
        libc::EAI_FAIL => c"Non-recoverable failure in name resolution".as_ptr(),
        libc::EAI_FAMILY => c"ai_family not supported".as_ptr(),
        libc::EAI_NONAME => c"Name or service not known".as_ptr(),
        libc::EAI_SERVICE => c"Service not supported for socket type".as_ptr(),
        libc::EAI_SOCKTYPE => c"Socket type not supported".as_ptr(),
        libc::EAI_OVERFLOW => c"Argument buffer overflow".as_ptr(),
        _ => c"Unknown getaddrinfo error".as_ptr(),
    }
}
