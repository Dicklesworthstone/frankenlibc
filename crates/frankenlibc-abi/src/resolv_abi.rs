//! ABI layer for selected resolver functions (`<netdb.h>`).
//!
//! Bootstrap scope:
//! - `getaddrinfo` (numeric host/service support with strict/hardened runtime policy)
//! - `freeaddrinfo`
//! - `getnameinfo` (numeric formatting)
//! - `gai_strerror`

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::int_plus_one)]

use std::ffi::{CStr, c_char, c_int, c_void};
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::malloc_abi::known_remaining;
use crate::runtime_policy;

#[inline]
fn repair_enabled(mode_heals: bool, action: MembraneAction) -> bool {
    mode_heals || matches!(action, MembraneAction::Repair(_))
}

#[inline]
fn stage_index(ordering: &[CheckStage; 7], stage: CheckStage) -> usize {
    ordering.iter().position(|s| *s == stage).unwrap_or(0)
}

#[inline]
fn resolver_stage_context(addr1: usize, addr2: usize) -> (bool, bool, [CheckStage; 7]) {
    let aligned = ((addr1 | addr2) & 0x7) == 0;
    let recent_page = (addr1 != 0 && known_remaining(addr1).is_some())
        || (addr2 != 0 && known_remaining(addr2).is_some());
    let ordering = runtime_policy::check_ordering(ApiFamily::Resolver, aligned, recent_page);
    (aligned, recent_page, ordering)
}

#[inline]
fn record_resolver_stage_outcome(
    ordering: &[CheckStage; 7],
    aligned: bool,
    recent_page: bool,
    exit_stage: Option<usize>,
) {
    runtime_policy::note_check_order_outcome(
        ApiFamily::Resolver,
        aligned,
        recent_page,
        ordering,
        exit_stage,
    );
}

unsafe fn opt_cstr<'a>(ptr: *const c_char) -> Option<&'a CStr> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller-provided C string pointer.
    Some(unsafe { CStr::from_ptr(ptr) })
}

enum HostsAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

fn resolve_hosts_subset(node: &str, family: c_int) -> Option<HostsAddress> {
    // Scope boundary: only deterministic files-backend lookup (`/etc/hosts`).
    // Network DNS/NSS backends are intentionally out-of-scope here.
    let content = std::fs::read("/etc/hosts").ok()?;
    let candidates = frankenlibc_core::resolv::lookup_hosts(&content, node.as_bytes());
    for candidate in candidates {
        let text = core::str::from_utf8(&candidate).ok()?;
        if (family == libc::AF_UNSPEC || family == libc::AF_INET)
            && let Ok(v4) = text.parse::<Ipv4Addr>()
        {
            return Some(HostsAddress::V4(v4));
        }
        if (family == libc::AF_UNSPEC || family == libc::AF_INET6)
            && let Ok(v6) = text.parse::<Ipv6Addr>()
        {
            return Some(HostsAddress::V6(v6));
        }
    }
    None
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> c_int {
    let (aligned, recent_page, ordering) = resolver_stage_context(node as usize, service as usize);
    if res.is_null() {
        record_resolver_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
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
        record_resolver_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
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
            record_resolver_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Bounds)),
            );
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
            } else if let Some(hosts_addr) = resolve_hosts_subset(text, family) {
                match hosts_addr {
                    // SAFETY: allocation helper returns ownership pointer.
                    HostsAddress::V4(v4) => unsafe { build_addrinfo_v4(v4, port, hints_ref) },
                    // SAFETY: allocation helper returns ownership pointer.
                    HostsAddress::V6(v6) => unsafe { build_addrinfo_v6(v6, port, hints_ref) },
                }
            } else if repair {
                global_healing_policy().record(&HealingAction::ReturnSafeDefault);
                // SAFETY: allocation helper returns ownership pointer.
                unsafe { build_addrinfo_v4(Ipv4Addr::LOCALHOST, port, hints_ref) }
            } else {
                record_resolver_stage_outcome(
                    &ordering,
                    aligned,
                    recent_page,
                    Some(stage_index(&ordering, CheckStage::Bounds)),
                );
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
    record_resolver_stage_outcome(&ordering, aligned, recent_page, None);
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, false);
    0
}

/// POSIX `freeaddrinfo`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn freeaddrinfo(mut res: *mut libc::addrinfo) {
    let (aligned, recent_page, ordering) = resolver_stage_context(res as usize, 0);
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Resolver, res as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        record_resolver_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 12, true);
        return;
    }
    if res.is_null() {
        record_resolver_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 12, false);
        return;
    }
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
    record_resolver_stage_outcome(&ordering, aligned, recent_page, None);
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 12, false);
}

/// POSIX `getnameinfo` (numeric bootstrap implementation).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnameinfo(
    sa: *const libc::sockaddr,
    salen: libc::socklen_t,
    host: *mut c_char,
    hostlen: libc::socklen_t,
    serv: *mut c_char,
    servlen: libc::socklen_t,
    _flags: c_int,
) -> c_int {
    let (aligned, recent_page, ordering) = resolver_stage_context(sa as usize, host as usize);
    if sa.is_null() {
        record_resolver_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
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
        record_resolver_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 20, true);
        return libc::EAI_FAIL;
    }
    let repair = repair_enabled(mode.heals_enabled(), decision.action);

    // SAFETY: caller provides valid sockaddr for given salen.
    let family = unsafe { (*sa).sa_family as c_int };
    let (host_text, serv_text) = match family {
        libc::AF_INET => {
            if (salen as usize) < size_of::<libc::sockaddr_in>() {
                record_resolver_stage_outcome(
                    &ordering,
                    aligned,
                    recent_page,
                    Some(stage_index(&ordering, CheckStage::Bounds)),
                );
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
                record_resolver_stage_outcome(
                    &ordering,
                    aligned,
                    recent_page,
                    Some(stage_index(&ordering, CheckStage::Bounds)),
                );
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
            record_resolver_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Bounds)),
            );
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 20, true);
            return libc::EAI_FAMILY;
        }
    };

    // SAFETY: output buffers are caller-provided according to getnameinfo contract.
    let host_truncated = unsafe {
        match write_c_buffer(host, hostlen, &host_text, repair) {
            Ok(truncated) => truncated,
            Err(err) => {
                record_resolver_stage_outcome(
                    &ordering,
                    aligned,
                    recent_page,
                    Some(stage_index(&ordering, CheckStage::Bounds)),
                );
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
                record_resolver_stage_outcome(
                    &ordering,
                    aligned,
                    recent_page,
                    Some(stage_index(&ordering, CheckStage::Bounds)),
                );
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
    record_resolver_stage_outcome(&ordering, aligned, recent_page, None);
    0
}

/// POSIX `gai_strerror`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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

// ---------------------------------------------------------------------------
// Legacy network database — GlibcCallThrough (deprecated but widely used)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "gethostbyname"]
    fn libc_gethostbyname(name: *const c_char) -> *mut c_void;
    #[link_name = "gethostbyaddr"]
    fn libc_gethostbyaddr(addr: *const c_void, len: libc::socklen_t, af: c_int) -> *mut c_void;
    #[link_name = "getservbyname"]
    fn libc_getservbyname(name: *const c_char, proto: *const c_char) -> *mut c_void;
    #[link_name = "getservbyport"]
    fn libc_getservbyport(port: c_int, proto: *const c_char) -> *mut c_void;
    #[link_name = "getprotobyname"]
    fn libc_getprotobyname(name: *const c_char) -> *mut c_void;
    #[link_name = "getprotobynumber"]
    fn libc_getprotobynumber(proto: c_int) -> *mut c_void;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname(name: *const c_char) -> *mut c_void {
    unsafe { libc_gethostbyname(name) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyaddr(addr: *const c_void, len: libc::socklen_t, af: c_int) -> *mut c_void {
    unsafe { libc_gethostbyaddr(addr, len, af) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyname(name: *const c_char, proto: *const c_char) -> *mut c_void {
    unsafe { libc_getservbyname(name, proto) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyport(port: c_int, proto: *const c_char) -> *mut c_void {
    unsafe { libc_getservbyport(port, proto) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobyname(name: *const c_char) -> *mut c_void {
    unsafe { libc_getprotobyname(name) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobynumber(proto: c_int) -> *mut c_void {
    unsafe { libc_getprotobynumber(proto) }
}
