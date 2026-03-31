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

use crate::errno_abi::set_abi_errno;
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
    #[allow(dead_code)]
    V6(Ipv6Addr),
}

fn resolve_hosts_subset(node: &str, family: c_int) -> Option<HostsAddress> {
    // Scope boundary: only deterministic files-backend lookup (`/etc/hosts`).
    // Network DNS/NSS backends are intentionally out-of-scope here.
    let content = std::fs::read("/etc/hosts").ok()?;
    let candidates = frankenlibc_core::resolv::lookup_hosts(&content, node.as_bytes());
    for candidate in candidates {
        let Ok(text) = core::str::from_utf8(&candidate) else {
            continue;
        };
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
    H_ERRNO_TLS.with(|cell| cell.set(value));
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
            // s_addr must be in network byte order (big-endian bytes in memory).
            // ip.octets() = [127,0,0,1]. We need memory bytes [0x7f,0x00,0x00,0x01].
            // On LE x86_64, u32 0x0100007f stores as bytes [7f,00,00,01]. Use from_ne_bytes.
            s_addr: u32::from_ne_bytes(ip.octets()),
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

    let mut nodes = Vec::new();

    match host_text {
        Some(text) => {
            if let Ok(v4) = text.parse::<Ipv4Addr>() {
                nodes.push(unsafe { build_addrinfo_v4(v4, port, hints_ref) });
            } else if let Ok(v6) = text.parse::<Ipv6Addr>() {
                nodes.push(unsafe { build_addrinfo_v6(v6, port, hints_ref) });
            } else {
                // Check /etc/hosts for all matches (subset only)
                let content = std::fs::read("/etc/hosts").unwrap_or_default();
                let candidates = frankenlibc_core::resolv::lookup_hosts(&content, text.as_bytes());
                for candidate in candidates {
                    if let Ok(c_text) = core::str::from_utf8(&candidate) {
                        if (family == libc::AF_UNSPEC || family == libc::AF_INET)
                            && let Ok(v4) = c_text.parse::<Ipv4Addr>()
                        {
                            nodes.push(unsafe { build_addrinfo_v4(v4, port, hints_ref) });
                        } else if (family == libc::AF_UNSPEC || family == libc::AF_INET6)
                            && let Ok(v6) = c_text.parse::<Ipv6Addr>()
                        {
                            nodes.push(unsafe { build_addrinfo_v6(v6, port, hints_ref) });
                        }
                    }
                }
            }

            if nodes.is_empty() {
                // Hostname not found in /etc/hosts and not a numeric address.
                // Delegate to host libc's getaddrinfo for real DNS resolution.
                type HostGetaddrinfoFn = unsafe extern "C" fn(
                    *const c_char,
                    *const c_char,
                    *const libc::addrinfo,
                    *mut *mut libc::addrinfo,
                ) -> c_int;
                if let Some(addr) = crate::host_resolve::resolve_host_symbol_raw("getaddrinfo") {
                    let host_fn: HostGetaddrinfoFn = unsafe { core::mem::transmute(addr) };
                    let rc = unsafe { host_fn(node, service, hints, res) };
                    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, rc != 0);
                    return rc;
                }
                if repair {
                    global_healing_policy().record(&HealingAction::ReturnSafeDefault);
                    nodes.push(unsafe { build_addrinfo_v4(Ipv4Addr::LOCALHOST, port, hints_ref) });
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
        }
        None => match family {
            libc::AF_INET6 => {
                nodes.push(unsafe { build_addrinfo_v6(Ipv6Addr::UNSPECIFIED, port, hints_ref) });
            }
            libc::AF_INET => {
                nodes.push(unsafe { build_addrinfo_v4(Ipv4Addr::UNSPECIFIED, port, hints_ref) });
            }
            _ => {
                nodes.push(unsafe { build_addrinfo_v4(Ipv4Addr::UNSPECIFIED, port, hints_ref) });
                nodes.push(unsafe { build_addrinfo_v6(Ipv6Addr::UNSPECIFIED, port, hints_ref) });
            }
        },
    }

    // Chain the nodes together.
    for i in 0..nodes.len().saturating_sub(1) {
        unsafe { (*nodes[i]).ai_next = nodes[i + 1] };
    }

    // SAFETY: output pointer is non-null and writable.
    unsafe { *res = nodes[0] };
    record_resolver_stage_outcome(&ordering, aligned, recent_page, None);
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, false);
    0
}

/// POSIX `freeaddrinfo`.
///
/// Delegates to the host libc's freeaddrinfo when available, since
/// getaddrinfo may return results allocated by the host (for DNS queries).
/// Our Box-allocated addrinfos are also freeable by the host since Box
/// uses the process allocator (which under LD_PRELOAD routes through
/// our malloc → host malloc).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn freeaddrinfo(res: *mut libc::addrinfo) {
    if res.is_null() {
        return;
    }
    // Native free: walk the linked list and free each node.
    // Under LD_PRELOAD, our malloc is the process allocator, so Box::from_raw
    // works for both our allocations and any host-getaddrinfo allocations.
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
    let mut cur = res;
    if cur.is_null() {
        record_resolver_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 12, false);
        return;
    }
    while !cur.is_null() {
        // SAFETY: traversing list allocated by getaddrinfo-compatible producer.
        let next = unsafe { (*cur).ai_next };
        let family = unsafe { (*cur).ai_family };
        let addr_ptr = unsafe { (*cur).ai_addr };
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
        let canon = unsafe { (*cur).ai_canonname };
        if !canon.is_null() {
            // SAFETY: canonname pointers are owned allocations.
            unsafe { drop(std::ffi::CString::from_raw(canon)) };
        }
        // SAFETY: node ownership belongs to caller of freeaddrinfo.
        unsafe { drop(Box::from_raw(cur)) };
        cur = next;
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
            // s_addr is in network byte order (big-endian bytes in memory).
            // Read raw bytes via to_ne_bytes to get [a,b,c,d] in memory order.
            let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
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
// Legacy network database — native implementations
// ---------------------------------------------------------------------------

/// Thread-local storage for servent results.
struct ServentTlsStorage {
    name: [c_char; 256],
    proto: [c_char; 32],
    aliases: [*mut c_char; 1],
    servent: libc::servent,
}

impl ServentTlsStorage {
    fn new() -> Self {
        Self {
            name: [0; 256],
            proto: [0; 32],
            aliases: [ptr::null_mut(); 1],
            servent: libc::servent {
                s_name: ptr::null_mut(),
                s_aliases: ptr::null_mut(),
                s_port: 0,
                s_proto: ptr::null_mut(),
            },
        }
    }
}

thread_local! {
    static SERVENT_TLS: RefCell<ServentTlsStorage> =
        RefCell::new(ServentTlsStorage::new());
}

/// Thread-local storage for protoent results.
struct ProtoentTlsStorage {
    name: [c_char; 256],
    aliases: [*mut c_char; 1],
    protoent: libc::protoent,
}

impl ProtoentTlsStorage {
    fn new() -> Self {
        Self {
            name: [0; 256],
            aliases: [ptr::null_mut(); 1],
            protoent: libc::protoent {
                p_name: ptr::null_mut(),
                p_aliases: ptr::null_mut(),
                p_proto: 0,
            },
        }
    }
}

thread_local! {
    static PROTOENT_TLS: RefCell<ProtoentTlsStorage> =
        RefCell::new(ProtoentTlsStorage::new());
}

/// Parse a single line from /etc/protocols.
///
/// Format: `<protocol-name> <number> [<alias>...]`
fn parse_protocols_line(line: &[u8]) -> Option<(Vec<u8>, i32)> {
    let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
        &line[..pos]
    } else {
        line
    };

    let mut fields = line
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|f| !f.is_empty());

    let name = fields.next()?;
    let number_str = core::str::from_utf8(fields.next()?).ok()?;
    let number: i32 = number_str.parse().ok()?;

    Some((name.to_vec(), number))
}

/// Copy a byte slice into a c_char buffer with NUL termination.
fn copy_to_cchar_buf(dst: &mut [c_char], src: &[u8]) {
    let copy_len = src.len().min(dst.len().saturating_sub(1));
    for (i, &b) in src[..copy_len].iter().enumerate() {
        dst[i] = b as c_char;
    }
    if copy_len < dst.len() {
        dst[copy_len] = 0;
    }
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
        unsafe { set_h_errnop(ptr::null_mut(), NO_RECOVERY_ERRNO) };
        unsafe { set_abi_errno(frankenlibc_core::errno::EACCES) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 18, true);
        return ptr::null_mut();
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    // SAFETY: optional C string pointer follows gethostbyname contract.
    let name_cstr = unsafe { opt_cstr(name) };
    let Some((resolved_name, addr)) = resolve_gethostbyname_target(name_cstr, repair) else {
        unsafe { set_h_errnop(ptr::null_mut(), HOST_NOT_FOUND_ERRNO) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 18, true);
        return ptr::null_mut();
    };

    // SAFETY: pointer returned references thread-local hostent storage.
    let hostent_ptr = unsafe { populate_tls_hostent(&resolved_name, addr) };
    unsafe { set_h_errnop(ptr::null_mut(), 0) };
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

/// Reentrant reverse lookup implementation for `gethostbyaddr_r`.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn gethostbyaddr_r_impl(
    addr: *const c_void,
    len: libc::socklen_t,
    af: c_int,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
    h_errnop: *mut c_int,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = ptr::null_mut() };
    }

    if addr.is_null() || af != libc::AF_INET || (len as usize) < 4 {
        unsafe { set_h_errnop(h_errnop, NO_RECOVERY_ERRNO) };
        return libc::EINVAL;
    }

    let octets = unsafe { std::slice::from_raw_parts(addr as *const u8, 4) };
    let ip = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    let ip_str = ip.to_string();

    let content = match std::fs::read("/etc/hosts") {
        Ok(c) => c,
        Err(_) => {
            unsafe { set_h_errnop(h_errnop, HOST_NOT_FOUND_ERRNO) };
            return libc::ENOENT;
        }
    };

    let hostnames = frankenlibc_core::resolv::reverse_lookup_hosts(&content, ip_str.as_bytes());
    if hostnames.is_empty() {
        unsafe { set_h_errnop(h_errnop, HOST_NOT_FOUND_ERRNO) };
        return libc::ENOENT;
    }

    match unsafe { write_reentrant_hostent(&hostnames[0], ip, result_buf, buf, buflen, result) } {
        Ok(()) => {
            unsafe { set_h_errnop(h_errnop, 0) };
            0
        }
        Err(code) => {
            unsafe { set_h_errnop(h_errnop, NO_RECOVERY_ERRNO) };
            code
        }
    }
}

/// POSIX `gethostbyaddr` — reverse DNS lookup by address.
///
/// Uses /etc/hosts for reverse lookup (no DNS queries).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyaddr(
    addr: *const c_void,
    len: libc::socklen_t,
    af: c_int,
) -> *mut c_void {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Resolver,
        addr as usize,
        len as usize,
        true,
        true,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_h_errnop(ptr::null_mut(), NO_RECOVERY_ERRNO) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 18, true);
        return ptr::null_mut();
    }

    if addr.is_null() {
        unsafe { set_h_errnop(ptr::null_mut(), NO_RECOVERY_ERRNO) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 5, true);
        return ptr::null_mut();
    }

    // Only support AF_INET for reverse lookup
    if af != libc::AF_INET || (len as usize) < 4 {
        unsafe { set_h_errnop(ptr::null_mut(), HOST_NOT_FOUND_ERRNO) };
        return ptr::null_mut();
    }

    // Read the IPv4 address
    let octets = unsafe { std::slice::from_raw_parts(addr as *const u8, 4) };
    let ip = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    let ip_str = ip.to_string();

    // Look up in /etc/hosts
    let content = match std::fs::read("/etc/hosts") {
        Ok(c) => c,
        Err(_) => {
            unsafe { set_h_errnop(ptr::null_mut(), HOST_NOT_FOUND_ERRNO) };
            return ptr::null_mut();
        }
    };

    let hostnames = frankenlibc_core::resolv::reverse_lookup_hosts(&content, ip_str.as_bytes());
    if hostnames.is_empty() {
        unsafe { set_h_errnop(ptr::null_mut(), HOST_NOT_FOUND_ERRNO) };
        return ptr::null_mut();
    }

    // Populate thread-local hostent storage with the first matching hostname
    let hostent_ptr = unsafe { populate_tls_hostent(&hostnames[0], ip) };
    unsafe { set_h_errnop(ptr::null_mut(), 0) };
    hostent_ptr
}

/// POSIX `getservbyname` — look up a service by name in /etc/services.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyname(name: *const c_char, proto: *const c_char) -> *mut c_void {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Resolver,
        name as usize,
        0,
        true,
        name.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    if name.is_null() {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 5, true);
        return ptr::null_mut();
    }

    let name_cstr = unsafe { CStr::from_ptr(name) };
    let proto_filter = if proto.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(proto) }.to_bytes())
    };

    let content = match std::fs::read("/etc/services") {
        Ok(c) => c,
        Err(_) => return ptr::null_mut(),
    };

    // Use core parser to find the service
    let port = match frankenlibc_core::resolv::lookup_service(
        &content,
        name_cstr.to_bytes(),
        proto_filter,
    ) {
        Some(p) => p,
        None => return ptr::null_mut(),
    };

    // Find the protocol string for this entry
    let proto_bytes: Vec<u8> = if let Some(pf) = proto_filter {
        pf.to_vec()
    } else {
        // Re-scan to find the actual protocol
        content
            .split(|&b| b == b'\n')
            .find_map(|line| {
                let entry = frankenlibc_core::resolv::parse_services_line(line)?;
                let requested_name = name_cstr.to_bytes();
                if entry.port == port
                    && (entry.name.eq_ignore_ascii_case(requested_name)
                        || entry
                            .aliases
                            .iter()
                            .any(|alias| alias.eq_ignore_ascii_case(requested_name)))
                {
                    Some(entry.protocol)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| b"tcp".to_vec())
    };

    SERVENT_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        copy_to_cchar_buf(&mut storage.name, name_cstr.to_bytes());
        copy_to_cchar_buf(&mut storage.proto, &proto_bytes);
        storage.aliases[0] = ptr::null_mut();
        storage.servent = libc::servent {
            s_name: storage.name.as_mut_ptr(),
            s_aliases: storage.aliases.as_mut_ptr(),
            s_port: (port as u16).to_be() as c_int,
            s_proto: storage.proto.as_mut_ptr(),
        };
        (&mut storage.servent as *mut libc::servent).cast::<c_void>()
    })
}

/// POSIX `getservbyport` — look up a service by port number in /etc/services.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyport(port: c_int, proto: *const c_char) -> *mut c_void {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Resolver,
        proto as usize,
        0,
        true,
        proto.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    let port_host = u16::from_be(port as u16);

    let proto_filter = if proto.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(proto) }.to_bytes())
    };

    let content = match std::fs::read("/etc/services") {
        Ok(c) => c,
        Err(_) => return ptr::null_mut(),
    };

    // Find the service entry matching this port
    let (svc_name, svc_proto) = match content.split(|&b| b == b'\n').find_map(|line| {
        let entry = frankenlibc_core::resolv::parse_services_line(line)?;
        if entry.port != port_host {
            return None;
        }
        if let Some(pf) = proto_filter
            && !entry.protocol.eq_ignore_ascii_case(pf)
        {
            return None;
        }
        Some((entry.name, entry.protocol))
    }) {
        Some(entry) => entry,
        None => return ptr::null_mut(),
    };

    SERVENT_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        copy_to_cchar_buf(&mut storage.name, &svc_name);
        copy_to_cchar_buf(&mut storage.proto, &svc_proto);
        storage.aliases[0] = ptr::null_mut();
        storage.servent = libc::servent {
            s_name: storage.name.as_mut_ptr(),
            s_aliases: storage.aliases.as_mut_ptr(),
            s_port: port,
            s_proto: storage.proto.as_mut_ptr(),
        };
        (&mut storage.servent as *mut libc::servent).cast::<c_void>()
    })
}

/// POSIX `getprotobyname` — look up a protocol by name in /etc/protocols.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobyname(name: *const c_char) -> *mut c_void {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Resolver,
        name as usize,
        0,
        true,
        name.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    if name.is_null() {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 5, true);
        return ptr::null_mut();
    }

    let name_cstr = unsafe { CStr::from_ptr(name) };
    let name_bytes = name_cstr.to_bytes();

    let content = match std::fs::read("/etc/protocols") {
        Ok(c) => c,
        Err(_) => return ptr::null_mut(),
    };

    let (proto_name, proto_num) = match content.split(|&b| b == b'\n').find_map(|line| {
        let (pname, pnum) = parse_protocols_line(line)?;
        if pname.eq_ignore_ascii_case(name_bytes) {
            Some((pname, pnum))
        } else {
            None
        }
    }) {
        Some(entry) => entry,
        None => return ptr::null_mut(),
    };

    PROTOENT_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        copy_to_cchar_buf(&mut storage.name, &proto_name);
        storage.aliases[0] = ptr::null_mut();
        storage.protoent = libc::protoent {
            p_name: storage.name.as_mut_ptr(),
            p_aliases: storage.aliases.as_mut_ptr(),
            p_proto: proto_num,
        };
        (&mut storage.protoent as *mut libc::protoent).cast::<c_void>()
    })
}

/// POSIX `getprotobynumber` — look up a protocol by number in /etc/protocols.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobynumber(proto: c_int) -> *mut c_void {
    let content = match std::fs::read("/etc/protocols") {
        Ok(c) => c,
        Err(_) => return ptr::null_mut(),
    };

    let (proto_name, proto_num) = match content.split(|&b| b == b'\n').find_map(|line| {
        let (pname, pnum) = parse_protocols_line(line)?;
        if pnum == proto {
            Some((pname, pnum))
        } else {
            None
        }
    }) {
        Some(entry) => entry,
        None => return ptr::null_mut(),
    };

    PROTOENT_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        copy_to_cchar_buf(&mut storage.name, &proto_name);
        storage.aliases[0] = ptr::null_mut();
        storage.protoent = libc::protoent {
            p_name: storage.name.as_mut_ptr(),
            p_aliases: storage.aliases.as_mut_ptr(),
            p_proto: proto_num,
        };
        (&mut storage.protoent as *mut libc::protoent).cast::<c_void>()
    })
}

// ===========================================================================
// h_errno — thread-local resolver error variable
// ===========================================================================

std::thread_local! {
    static H_ERRNO_TLS: std::cell::Cell<c_int> = const { std::cell::Cell::new(0) };
}

/// `__h_errno_location` — return thread-local h_errno pointer.
/// glibc's h_errno macro expands to `(*__h_errno_location())`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __h_errno_location() -> *mut c_int {
    H_ERRNO_TLS.with(|cell| cell.as_ptr())
}
