//! ABI layer for selected resolver functions (`<netdb.h>`).
//!
//! Bootstrap scope:
//! - `getaddrinfo` (numeric host/service support with strict/hardened runtime policy)
//! - `freeaddrinfo`
//! - `getnameinfo` (numeric formatting)
//! - `gai_strerror`

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::int_plus_one)]

use std::cell::RefCell;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::mem::{align_of, size_of};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::malloc_abi::known_remaining;
use crate::runtime_policy;

const HOST_NOT_FOUND_ERRNO: c_int = 1;
const NO_RECOVERY_ERRNO: c_int = 3;

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

fn resolve_gethostbyname_ipv4(node: &str) -> Option<Ipv4Addr> {
    if let Ok(v4) = node.parse::<Ipv4Addr>() {
        return Some(v4);
    }
    match resolve_hosts_subset(node, libc::AF_INET) {
        Some(HostsAddress::V4(v4)) => Some(v4),
        _ => None,
    }
}

fn resolve_gethostbyname_target(name: Option<&CStr>, repair: bool) -> Option<(Vec<u8>, Ipv4Addr)> {
    if let Some(name_cstr) = name
        && let Ok(node) = name_cstr.to_str()
        && let Some(v4) = resolve_gethostbyname_ipv4(node)
    {
        return Some((name_cstr.to_bytes().to_vec(), v4));
    }
    if repair {
        global_healing_policy().record(&HealingAction::ReturnSafeDefault);
        return Some((b"localhost".to_vec(), Ipv4Addr::LOCALHOST));
    }
    None
}

#[inline]
fn align_up(offset: usize, align: usize) -> usize {
    if align <= 1 {
        return offset;
    }
    (offset + (align - 1)) & !(align - 1)
}

#[inline]
unsafe fn set_h_errnop(h_errnop: *mut c_int, value: c_int) {
    if !h_errnop.is_null() {
        // SAFETY: caller-provided out-parameter pointer.
        unsafe { *h_errnop = value };
    }
}

struct HostentTlsStorage {
    name: [c_char; 256],
    aliases: [*mut c_char; 1],
    addr_list: [*mut c_char; 2],
    addr: [u8; 4],
    hostent: libc::hostent,
}

impl HostentTlsStorage {
    fn new() -> Self {
        Self {
            name: [0; 256],
            aliases: [ptr::null_mut(); 1],
            addr_list: [ptr::null_mut(); 2],
            addr: [0; 4],
            hostent: libc::hostent {
                h_name: ptr::null_mut(),
                h_aliases: ptr::null_mut(),
                h_addrtype: 0,
                h_length: 0,
                h_addr_list: ptr::null_mut(),
            },
        }
    }
}

thread_local! {
    static GETHOSTBYNAME_TLS: RefCell<HostentTlsStorage> =
        RefCell::new(HostentTlsStorage::new());
}

fn with_tls_hostent<R>(f: impl FnOnce(&mut HostentTlsStorage) -> R) -> R {
    GETHOSTBYNAME_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        f(&mut storage)
    })
}

unsafe fn populate_tls_hostent(name_bytes: &[u8], ip: Ipv4Addr) -> *mut c_void {
    with_tls_hostent(|storage| {
        storage.name.fill(0);
        let max_name = storage.name.len().saturating_sub(1);
        let copy_len = name_bytes.len().min(max_name);
        for (index, byte) in name_bytes.iter().take(copy_len).copied().enumerate() {
            storage.name[index] = byte as c_char;
        }

        storage.addr = ip.octets();
        storage.aliases[0] = ptr::null_mut();
        storage.addr_list[0] = storage.addr.as_mut_ptr().cast::<c_char>();
        storage.addr_list[1] = ptr::null_mut();
        storage.hostent = libc::hostent {
            h_name: storage.name.as_mut_ptr(),
            h_aliases: storage.aliases.as_mut_ptr(),
            h_addrtype: libc::AF_INET,
            h_length: 4,
            h_addr_list: storage.addr_list.as_mut_ptr(),
        };
        (&mut storage.hostent as *mut libc::hostent).cast::<c_void>()
    })
}

unsafe fn write_reentrant_hostent(
    name_bytes: &[u8],
    ip: Ipv4Addr,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> Result<(), c_int> {
    if result_buf.is_null() || buf.is_null() {
        return Err(libc::EINVAL);
    }
    if result.is_null() {
        return Err(libc::EINVAL);
    }

    let name_len = name_bytes.len().saturating_add(1);
    if name_len > buflen {
        return Err(libc::ERANGE);
    }
    // SAFETY: bounds checked above against buflen.
    unsafe {
        ptr::copy_nonoverlapping(name_bytes.as_ptr().cast::<c_char>(), buf, name_bytes.len());
        *buf.add(name_bytes.len()) = 0;
    }
    let name_ptr = buf;
    let mut offset = name_len;

    offset = align_up(offset, align_of::<*mut c_char>());
    if offset + 4 > buflen {
        return Err(libc::ERANGE);
    }
    // SAFETY: bounds checked above.
    let addr_ptr = unsafe { buf.add(offset).cast::<u8>() };
    let addr = ip.octets();
    // SAFETY: addr_ptr points to at least 4 writable bytes.
    unsafe { ptr::copy_nonoverlapping(addr.as_ptr(), addr_ptr, addr.len()) };
    offset += 4;

    offset = align_up(offset, align_of::<*mut c_char>());
    let aliases_bytes = size_of::<*mut c_char>();
    if offset + aliases_bytes > buflen {
        return Err(libc::ERANGE);
    }
    // SAFETY: bounds checked above and alignment enforced.
    let aliases_ptr = unsafe { buf.add(offset).cast::<*mut c_char>() };
    // SAFETY: aliases_ptr points to one pointer-sized slot.
    unsafe { *aliases_ptr = ptr::null_mut() };
    offset += aliases_bytes;

    offset = align_up(offset, align_of::<*mut c_char>());
    let addr_list_bytes = size_of::<*mut c_char>() * 2;
    if offset + addr_list_bytes > buflen {
        return Err(libc::ERANGE);
    }
    // SAFETY: bounds checked above and alignment enforced.
    let addr_list_ptr = unsafe { buf.add(offset).cast::<*mut c_char>() };
    // SAFETY: addr_list_ptr points to two pointer-sized slots.
    unsafe {
        *addr_list_ptr = addr_ptr.cast::<c_char>();
        *addr_list_ptr.add(1) = ptr::null_mut();
    }

    // SAFETY: result_buf points to caller-owned hostent storage.
    let hostent = unsafe { &mut *result_buf.cast::<libc::hostent>() };
    hostent.h_name = name_ptr;
    hostent.h_aliases = aliases_ptr;
    hostent.h_addrtype = libc::AF_INET;
    hostent.h_length = 4;
    hostent.h_addr_list = addr_list_ptr;

    // SAFETY: result pointer is valid and writable by caller contract.
    unsafe { *result = result_buf };
    Ok(())
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
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Resolver,
        name as usize,
        0,
        true,
        name.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 18, true);
        return ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    // SAFETY: optional C string pointer follows gethostbyname contract.
    let name_cstr = unsafe { opt_cstr(name) };
    let Some((resolved_name, addr)) = resolve_gethostbyname_target(name_cstr, repair) else {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 18, true);
        return ptr::null_mut();
    };

    // SAFETY: pointer returned references thread-local hostent storage.
    let hostent_ptr = unsafe { populate_tls_hostent(&resolved_name, addr) };
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 18, false);
    hostent_ptr
}

pub(crate) unsafe fn gethostbyname_r_impl(
    name: *const c_char,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
    h_errnop: *mut c_int,
) -> c_int {
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Resolver,
        name as usize,
        buflen,
        true,
        name.is_null(),
        0,
    );
    if !result.is_null() {
        // SAFETY: caller-provided out-parameter pointer.
        unsafe { *result = ptr::null_mut() };
    }
    if matches!(decision.action, MembraneAction::Deny) {
        // SAFETY: optional h_errno pointer from caller.
        unsafe { set_h_errnop(h_errnop, NO_RECOVERY_ERRNO) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, true);
        return libc::EACCES;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    // SAFETY: optional C string pointer follows gethostbyname_r contract.
    let name_cstr = unsafe { opt_cstr(name) };
    let Some((resolved_name, addr)) = resolve_gethostbyname_target(name_cstr, repair) else {
        // SAFETY: optional h_errno pointer from caller.
        unsafe { set_h_errnop(h_errnop, HOST_NOT_FOUND_ERRNO) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, true);
        return libc::ENOENT;
    };

    // SAFETY: all pointers/length validated within helper.
    match unsafe { write_reentrant_hostent(&resolved_name, addr, result_buf, buf, buflen, result) }
    {
        Ok(()) => {
            // SAFETY: optional h_errno pointer from caller.
            unsafe { set_h_errnop(h_errnop, 0) };
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, false);
            0
        }
        Err(code) => {
            // SAFETY: optional h_errno pointer from caller.
            unsafe { set_h_errnop(h_errnop, NO_RECOVERY_ERRNO) };
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, true);
            code
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyaddr(
    addr: *const c_void,
    len: libc::socklen_t,
    af: c_int,
) -> *mut c_void {
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
