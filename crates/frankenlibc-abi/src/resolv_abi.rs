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
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::UNIX_EPOCH;

use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

const HOST_NOT_FOUND_ERRNO: c_int = 1;
const NO_RECOVERY_ERRNO: c_int = 3;
const HOSTS_PATH: &str = "/etc/hosts";
const SERVICES_PATH: &str = "/etc/services";
const PROC_NET_ROUTE_PATH: &str = "/proc/net/route";
const PROC_NET_IF_INET6_PATH: &str = "/proc/net/if_inet6";

// ---------------------------------------------------------------------------
// DNS Evidence Metrics (bd-1y7)
// ---------------------------------------------------------------------------

/// Counters for DNS stub resolver evidence logging.
/// Tracks query outcomes for timeout/fallback/parse failure analysis.
pub struct DnsMetrics {
    /// Total UDP DNS queries attempted.
    pub queries_attempted: AtomicU64,
    /// Queries that succeeded with valid response.
    pub queries_success: AtomicU64,
    /// Queries that timed out (recvfrom returned <= 0).
    pub queries_timeout: AtomicU64,
    /// Queries that failed to send (socket or sendto error).
    pub queries_send_error: AtomicU64,
    /// Queries where response parsing failed.
    pub queries_parse_error: AtomicU64,
    /// Queries that returned NXDOMAIN.
    pub queries_nxdomain: AtomicU64,
    /// Queries that returned other DNS errors (SERVFAIL, etc).
    pub queries_dns_error: AtomicU64,
}

impl DnsMetrics {
    const fn new() -> Self {
        Self {
            queries_attempted: AtomicU64::new(0),
            queries_success: AtomicU64::new(0),
            queries_timeout: AtomicU64::new(0),
            queries_send_error: AtomicU64::new(0),
            queries_parse_error: AtomicU64::new(0),
            queries_nxdomain: AtomicU64::new(0),
            queries_dns_error: AtomicU64::new(0),
        }
    }

    /// Snapshot all counters as a tuple for testing/evidence.
    pub fn snapshot(&self) -> DnsMetricsSnapshot {
        DnsMetricsSnapshot {
            queries_attempted: self.queries_attempted.load(AtomicOrdering::Relaxed),
            queries_success: self.queries_success.load(AtomicOrdering::Relaxed),
            queries_timeout: self.queries_timeout.load(AtomicOrdering::Relaxed),
            queries_send_error: self.queries_send_error.load(AtomicOrdering::Relaxed),
            queries_parse_error: self.queries_parse_error.load(AtomicOrdering::Relaxed),
            queries_nxdomain: self.queries_nxdomain.load(AtomicOrdering::Relaxed),
            queries_dns_error: self.queries_dns_error.load(AtomicOrdering::Relaxed),
        }
    }
}

/// Snapshot of DNS metrics at a point in time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsMetricsSnapshot {
    pub queries_attempted: u64,
    pub queries_success: u64,
    pub queries_timeout: u64,
    pub queries_send_error: u64,
    pub queries_parse_error: u64,
    pub queries_nxdomain: u64,
    pub queries_dns_error: u64,
}

/// Global DNS metrics instance.
static DNS_METRICS: DnsMetrics = DnsMetrics::new();

/// Get a snapshot of the current DNS metrics.
pub fn dns_metrics_snapshot() -> DnsMetricsSnapshot {
    DNS_METRICS.snapshot()
}
const HOSTS_PATH_ENV: &str = "FRANKENLIBC_HOSTS_PATH";
const SERVICES_PATH_ENV: &str = "FRANKENLIBC_SERVICES_PATH";
const PROC_NET_ROUTE_PATH_ENV: &str = "FRANKENLIBC_PROC_NET_ROUTE_PATH";
const PROC_NET_IF_INET6_PATH_ENV: &str = "FRANKENLIBC_PROC_NET_IF_INET6_PATH";

fn tracked_region_fits(ptr: *const c_void, len: usize) -> bool {
    known_remaining(ptr as usize).is_none_or(|remaining| len <= remaining)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    modified_ns: u128,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct BackendCacheMetrics {
    hits: u64,
    misses: u64,
    reloads: u64,
    invalidations: u64,
}

struct BackendFileCache {
    default_path: &'static str,
    env_key: &'static str,
    source_path: PathBuf,
    file_cache: Option<Vec<u8>>,
    cache_fingerprint: Option<FileFingerprint>,
    cache_generation: u64,
    cache_metrics: BackendCacheMetrics,
    last_io_error: Option<c_int>,
}

impl BackendFileCache {
    fn new(default_path: &'static str, env_key: &'static str) -> Self {
        Self {
            default_path,
            env_key,
            source_path: configured_backend_path(default_path, env_key),
            file_cache: None,
            cache_fingerprint: None,
            cache_generation: 0,
            cache_metrics: BackendCacheMetrics::default(),
            last_io_error: None,
        }
    }

    fn configured_source_path(&self) -> PathBuf {
        configured_backend_path(self.default_path, self.env_key)
    }

    fn refresh_source_path_from_env(&mut self) {
        let configured = self.configured_source_path();
        if configured == self.source_path {
            return;
        }

        self.source_path = configured;
        if self.file_cache.is_some() {
            self.cache_metrics.invalidations += 1;
        }
        self.file_cache = None;
        self.cache_fingerprint = None;
        self.last_io_error = None;
    }

    fn file_fingerprint(path: &Path) -> Option<FileFingerprint> {
        let metadata = std::fs::metadata(path).ok()?;
        let modified_ns = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_nanos());

        Some(FileFingerprint {
            len: metadata.len(),
            modified_ns,
            inode: metadata.ino(),
        })
    }

    fn refresh_cache(&mut self) {
        self.refresh_source_path_from_env();
        let current_fp = Self::file_fingerprint(&self.source_path);

        if let (Some(_), Some(cached_fp), Some(now_fp)) =
            (&self.file_cache, self.cache_fingerprint, current_fp)
            && cached_fp == now_fp
        {
            self.cache_metrics.hits += 1;
            self.last_io_error = None;
            return;
        }

        self.cache_metrics.misses += 1;

        match std::fs::read(&self.source_path) {
            Ok(bytes) => {
                let next_fp = Self::file_fingerprint(&self.source_path)
                    .or(current_fp)
                    .unwrap_or(FileFingerprint {
                        len: bytes.len() as u64,
                        modified_ns: 0,
                        inode: 0,
                    });
                let had_cache = self.file_cache.is_some();

                self.file_cache = Some(bytes);
                self.cache_fingerprint = Some(next_fp);
                self.cache_generation = self.cache_generation.wrapping_add(1);
                self.cache_metrics.reloads += 1;
                self.last_io_error = None;

                if had_cache {
                    self.cache_metrics.invalidations += 1;
                }
            }
            Err(err) => {
                if self.file_cache.is_some() {
                    self.cache_metrics.invalidations += 1;
                }
                self.file_cache = None;
                self.cache_fingerprint = None;
                self.last_io_error =
                    Some(err.raw_os_error().unwrap_or(frankenlibc_core::errno::EIO));
            }
        }
    }

    fn read_snapshot(&mut self) -> std::io::Result<Vec<u8>> {
        self.refresh_cache();
        match &self.file_cache {
            Some(bytes) => Ok(bytes.clone()),
            None => Err(std::io::Error::from_raw_os_error(
                self.last_io_error
                    .unwrap_or(frankenlibc_core::errno::ENOENT),
            )),
        }
    }
}

thread_local! {
    static HOSTS_BACKEND_TLS: RefCell<BackendFileCache> =
        RefCell::new(BackendFileCache::new(HOSTS_PATH, HOSTS_PATH_ENV));
    static SERVICES_BACKEND_TLS: RefCell<BackendFileCache> =
        RefCell::new(BackendFileCache::new(SERVICES_PATH, SERVICES_PATH_ENV));
    static PROC_NET_ROUTE_TLS: RefCell<BackendFileCache> =
        RefCell::new(BackendFileCache::new(PROC_NET_ROUTE_PATH, PROC_NET_ROUTE_PATH_ENV));
    static PROC_NET_IF_INET6_TLS: RefCell<BackendFileCache> =
        RefCell::new(BackendFileCache::new(PROC_NET_IF_INET6_PATH, PROC_NET_IF_INET6_PATH_ENV));
}

fn configured_backend_path(default_path: &str, env_key: &str) -> PathBuf {
    std::env::var_os(env_key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default_path))
}

fn read_hosts_backend() -> std::io::Result<Vec<u8>> {
    HOSTS_BACKEND_TLS.with(|cell| cell.borrow_mut().read_snapshot())
}

fn read_services_backend() -> std::io::Result<Vec<u8>> {
    SERVICES_BACKEND_TLS.with(|cell| cell.borrow_mut().read_snapshot())
}

fn read_addrconfig_state_snapshot() -> Option<frankenlibc_core::resolv::AddrConfigState> {
    let route = PROC_NET_ROUTE_TLS.with(|cell| cell.borrow_mut().read_snapshot().ok())?;
    let if_inet6 = PROC_NET_IF_INET6_TLS.with(|cell| cell.borrow_mut().read_snapshot().ok())?;
    Some(frankenlibc_core::resolv::addrconfig_state_from_procfs(
        &route, &if_inet6,
    ))
}

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

unsafe fn opt_cstr<'a>(ptr: *const c_char) -> Result<Option<&'a CStr>, ()> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: caller supplies a C-string pointer; known allocator bounds stop
    // the scan before the end of tracked malloc-backed objects.
    let (len, terminated) =
        unsafe { crate::util::scan_c_string(ptr, known_remaining(ptr as usize)) };
    if !terminated {
        return Err(());
    }
    let Some(slice_len) = len.checked_add(1) else {
        return Err(());
    };
    // SAFETY: scan_c_string found a NUL at len, so len + 1 bytes are readable
    // under the same C-string precondition and include exactly the terminator.
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), slice_len) };
    // SAFETY: the slice ends at the first observed NUL, so it has a single
    // trailing terminator and no interior NUL bytes.
    Ok(Some(unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }))
}

unsafe fn required_cstr_bytes<'a>(ptr: *const c_char) -> Option<&'a [u8]> {
    unsafe { opt_cstr(ptr) }.ok().flatten().map(CStr::to_bytes)
}

enum HostsAddress {
    V4(Ipv4Addr),
    #[allow(dead_code)]
    V6(Ipv6Addr),
}

fn resolve_hosts_subset(node: &str, family: c_int) -> Option<HostsAddress> {
    // Scope boundary: only deterministic files-backend lookup (`/etc/hosts`).
    // Network DNS/NSS backends are intentionally out-of-scope here.
    let content = read_hosts_backend().ok()?;
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

fn lookup_hosts_ipv4_by_name(name: &[u8]) -> Option<Ipv4Addr> {
    let content = read_hosts_backend().ok()?;
    let candidates = frankenlibc_core::resolv::lookup_hosts(&content, name);
    for candidate in candidates {
        let Ok(text) = core::str::from_utf8(&candidate) else {
            continue;
        };
        if let Ok(v4) = text.parse::<Ipv4Addr>() {
            return Some(v4);
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
fn is_aligned_for<T>(ptr: *const c_void) -> bool {
    (ptr as usize).is_multiple_of(align_of::<T>())
}

fn aligned_buffer_offset(base: *const c_char, min_offset: usize, align: usize) -> Option<usize> {
    if align <= 1 {
        return Some(min_offset);
    }
    let addr = (base as usize).checked_add(min_offset)?;
    let rem = addr % align;
    let padding = if rem == 0 { 0 } else { align - rem };
    min_offset.checked_add(padding)
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
    if !is_aligned_for::<libc::hostent>(result_buf) {
        return Err(libc::EINVAL);
    }

    let name_len = name_bytes.len().checked_add(1).ok_or(libc::ERANGE)?;
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

    offset = aligned_buffer_offset(buf, offset, align_of::<u8>()).ok_or(libc::ERANGE)?;
    let addr_end = offset.checked_add(4).ok_or(libc::ERANGE)?;
    if addr_end > buflen {
        return Err(libc::ERANGE);
    }
    // SAFETY: bounds checked above.
    let addr_ptr = unsafe { buf.add(offset).cast::<u8>() };
    let addr = ip.octets();
    // SAFETY: addr_ptr points to at least 4 writable bytes.
    unsafe { ptr::copy_nonoverlapping(addr.as_ptr(), addr_ptr, addr.len()) };
    offset = addr_end;

    offset = aligned_buffer_offset(buf, offset, align_of::<*mut c_char>()).ok_or(libc::ERANGE)?;
    let aliases_bytes = size_of::<*mut c_char>();
    let aliases_end = offset.checked_add(aliases_bytes).ok_or(libc::ERANGE)?;
    if aliases_end > buflen {
        return Err(libc::ERANGE);
    }
    // SAFETY: bounds checked above and alignment enforced.
    let aliases_ptr = unsafe { buf.add(offset).cast::<*mut c_char>() };
    // SAFETY: aliases_ptr points to one pointer-sized slot.
    unsafe { *aliases_ptr = ptr::null_mut() };
    offset = aliases_end;

    offset = aligned_buffer_offset(buf, offset, align_of::<*mut c_char>()).ok_or(libc::ERANGE)?;
    let addr_list_bytes = size_of::<*mut c_char>() * 2;
    let addr_list_end = offset.checked_add(addr_list_bytes).ok_or(libc::ERANGE)?;
    if addr_list_end > buflen {
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

/// Contiguous addrinfo + sockaddr_in allocation.
///
/// Uses a single allocation for both the addrinfo and the sockaddr_in, so that
/// freeaddrinfo can use a single free() call. This matches glibc's behavior.
#[repr(C)]
struct ContiguousAddrinfoV4 {
    ai: libc::addrinfo,
    sockaddr: libc::sockaddr_in,
}

unsafe fn build_addrinfo_v4(
    ip: Ipv4Addr,
    port: u16,
    hints: Option<&libc::addrinfo>,
) -> *mut libc::addrinfo {
    let (flags, socktype, protocol) = hints
        .map(|h| (h.ai_flags, h.ai_socktype, h.ai_protocol))
        .unwrap_or((0, 0, 0));

    // Allocate contiguously so freeaddrinfo can use a single free().
    let layout = std::alloc::Layout::new::<ContiguousAddrinfoV4>();
    let ptr = unsafe { crate::malloc_abi::malloc(layout.size()) };
    if ptr.is_null() {
        return ptr::null_mut();
    }
    let block = ptr.cast::<ContiguousAddrinfoV4>();

    // Initialize sockaddr_in.
    let sockaddr_ptr = unsafe { ptr::addr_of_mut!((*block).sockaddr) };
    unsafe {
        ptr::write(
            sockaddr_ptr,
            libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: port.to_be(),
                sin_addr: libc::in_addr {
                    // s_addr must be in network byte order (big-endian bytes in memory).
                    // ip.octets() = [127,0,0,1]. We need memory bytes [0x7f,0x00,0x00,0x01].
                    // On LE x86_64, u32 0x0100007f stores as bytes [7f,00,00,01]. Use from_ne_bytes.
                    s_addr: u32::from_ne_bytes(ip.octets()),
                },
                sin_zero: [0; 8],
            },
        );
    }

    // Initialize addrinfo, pointing to the embedded sockaddr.
    let ai_ptr = unsafe { ptr::addr_of_mut!((*block).ai) };
    unsafe {
        ptr::write(
            ai_ptr,
            libc::addrinfo {
                ai_flags: flags,
                ai_family: libc::AF_INET,
                ai_socktype: socktype,
                ai_protocol: protocol,
                ai_addrlen: size_of::<libc::sockaddr_in>() as libc::socklen_t,
                ai_addr: sockaddr_ptr.cast::<libc::sockaddr>(),
                ai_canonname: ptr::null_mut(),
                ai_next: ptr::null_mut(),
            },
        );
    }
    ai_ptr
}

/// Contiguous addrinfo + sockaddr_in6 allocation.
///
/// Uses a single allocation for both the addrinfo and the sockaddr_in6, so that
/// freeaddrinfo can use a single free() call. This matches glibc's behavior.
#[repr(C)]
struct ContiguousAddrinfoV6 {
    ai: libc::addrinfo,
    sockaddr: libc::sockaddr_in6,
}

unsafe fn build_addrinfo_v6(
    ip: Ipv6Addr,
    port: u16,
    hints: Option<&libc::addrinfo>,
) -> *mut libc::addrinfo {
    let (flags, socktype, protocol) = hints
        .map(|h| (h.ai_flags, h.ai_socktype, h.ai_protocol))
        .unwrap_or((0, 0, 0));

    // Allocate contiguously so freeaddrinfo can use a single free().
    let layout = std::alloc::Layout::new::<ContiguousAddrinfoV6>();
    let ptr = unsafe { crate::malloc_abi::malloc(layout.size()) };
    if ptr.is_null() {
        return ptr::null_mut();
    }
    let block = ptr.cast::<ContiguousAddrinfoV6>();

    // Initialize sockaddr_in6.
    let sockaddr_ptr = unsafe { ptr::addr_of_mut!((*block).sockaddr) };
    unsafe {
        ptr::write(
            sockaddr_ptr,
            libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: port.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: ip.octets(),
                },
                sin6_scope_id: 0,
            },
        );
    }

    // Initialize addrinfo, pointing to the embedded sockaddr.
    let ai_ptr = unsafe { ptr::addr_of_mut!((*block).ai) };
    unsafe {
        ptr::write(
            ai_ptr,
            libc::addrinfo {
                ai_flags: flags,
                ai_family: libc::AF_INET6,
                ai_socktype: socktype,
                ai_protocol: protocol,
                ai_addrlen: size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                ai_addr: sockaddr_ptr.cast::<libc::sockaddr>(),
                ai_canonname: ptr::null_mut(),
                ai_next: ptr::null_mut(),
            },
        );
    }
    ai_ptr
}

unsafe fn free_addrinfo_node(node: *mut libc::addrinfo) {
    if !node.is_null() {
        // SAFETY: node is a single addrinfo allocation owned by this resolver path.
        unsafe { crate::malloc_abi::free(node.cast::<c_void>()) };
    }
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

// ---------------------------------------------------------------------------
// Native DNS stub resolver (UDP query to nameservers)
// ---------------------------------------------------------------------------

/// Perform a single UDP DNS query to a nameserver.
/// Returns parsed answer records on success, None on network/timeout/parse error.
/// Records evidence metrics for each query outcome (bd-1y7).
fn udp_dns_query(
    hostname: &[u8],
    qtype_val: u16,
    nameserver: std::net::IpAddr,
    timeout_secs: u32,
) -> Option<Vec<frankenlibc_core::resolv::dns::DnsRecord>> {
    use frankenlibc_core::resolv::dns::{
        DNS_HEADER_SIZE, DNS_MAX_UDP_SIZE, DnsMessage, parse_dns_response, rcode,
    };

    DNS_METRICS
        .queries_attempted
        .fetch_add(1, AtomicOrdering::Relaxed);

    // Generate transaction ID
    let id = {
        let mut h = 0u16;
        for &b in hostname {
            h = h.wrapping_mul(31).wrapping_add(b as u16);
        }
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let _ = unsafe {
            raw_syscall::sys_clock_gettime(libc::CLOCK_MONOTONIC, &mut ts as *mut _ as *mut u8)
        };
        h ^ (ts.tv_nsec as u16)
    };

    // Encode query
    let msg = DnsMessage::new_query(id, hostname, qtype_val);
    let mut send_buf = [0u8; DNS_MAX_UDP_SIZE];
    let Some(send_len) = msg.encode(&mut send_buf) else {
        DNS_METRICS
            .queries_parse_error
            .fetch_add(1, AtomicOrdering::Relaxed);
        return None;
    };

    // Create UDP socket via raw syscall
    let af = if nameserver.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = match raw_syscall::sys_socket(af, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) {
        Ok(fd) => fd,
        Err(_) => {
            DNS_METRICS
                .queries_send_error
                .fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        }
    };

    // Set receive timeout
    let tv = libc::timeval {
        tv_sec: timeout_secs as i64,
        tv_usec: 0,
    };
    let _ = unsafe {
        raw_syscall::sys_setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const u8,
            core::mem::size_of::<libc::timeval>(),
        )
    };

    // Build destination sockaddr and send
    let sent = if nameserver.is_ipv4() {
        let octets = match nameserver {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!(),
        };
        let sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 53u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(octets),
            },
            sin_zero: [0; 8],
        };
        unsafe {
            raw_syscall::sys_sendto(
                fd,
                send_buf.as_ptr(),
                send_len,
                0,
                &sa as *const libc::sockaddr_in as *const u8,
                core::mem::size_of::<libc::sockaddr_in>(),
            )
        }
        .map(|n| n as i64)
        .unwrap_or(-1)
    } else {
        let octets = match nameserver {
            std::net::IpAddr::V6(v6) => v6.octets(),
            _ => unreachable!(),
        };
        let mut sa: libc::sockaddr_in6 = unsafe { core::mem::zeroed() };
        sa.sin6_family = libc::AF_INET6 as u16;
        sa.sin6_port = 53u16.to_be();
        sa.sin6_addr.s6_addr = octets;
        unsafe {
            raw_syscall::sys_sendto(
                fd,
                send_buf.as_ptr(),
                send_len,
                0,
                &sa as *const libc::sockaddr_in6 as *const u8,
                core::mem::size_of::<libc::sockaddr_in6>(),
            )
        }
        .map(|n| n as i64)
        .unwrap_or(-1)
    };

    if sent < 0 {
        let _ = raw_syscall::sys_close(fd);
        DNS_METRICS
            .queries_send_error
            .fetch_add(1, AtomicOrdering::Relaxed);
        return None;
    }

    // Receive response
    let mut recv_buf = [0u8; DNS_MAX_UDP_SIZE];
    let received = unsafe {
        raw_syscall::sys_recvfrom(
            fd,
            recv_buf.as_mut_ptr(),
            DNS_MAX_UDP_SIZE,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    }
    .map(|n| n as i64)
    .unwrap_or(-1);
    let _ = raw_syscall::sys_close(fd);

    if received < DNS_HEADER_SIZE as i64 {
        DNS_METRICS
            .queries_timeout
            .fetch_add(1, AtomicOrdering::Relaxed);
        return None;
    }

    // Parse response and record outcome metrics
    let result = parse_dns_response(&recv_buf[..received as usize], id);
    match &result {
        Some(records) if records.is_empty() => {
            // Empty records typically means NXDOMAIN
            DNS_METRICS
                .queries_nxdomain
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
        Some(_) => {
            DNS_METRICS
                .queries_success
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
        None => {
            // Check if we got a DNS error code vs parse failure
            if received >= DNS_HEADER_SIZE as i64 {
                let header = frankenlibc_core::resolv::dns::DnsHeader::decode(&recv_buf);
                if let Some(h) = header {
                    if h.rcode() != rcode::NOERROR {
                        DNS_METRICS
                            .queries_dns_error
                            .fetch_add(1, AtomicOrdering::Relaxed);
                    } else {
                        DNS_METRICS
                            .queries_parse_error
                            .fetch_add(1, AtomicOrdering::Relaxed);
                    }
                } else {
                    DNS_METRICS
                        .queries_parse_error
                        .fetch_add(1, AtomicOrdering::Relaxed);
                }
            } else {
                DNS_METRICS
                    .queries_parse_error
                    .fetch_add(1, AtomicOrdering::Relaxed);
            }
        }
    }
    result
}

/// Resolve hostname via DNS stub resolver. Returns resolved addresses.
fn native_dns_resolve(
    hostname: &[u8],
    want_v4: bool,
    want_v6: bool,
) -> frankenlibc_core::resolv::dns::DnsResolution {
    use frankenlibc_core::resolv::dns::{DnsResolution, qtype};

    let config = match std::fs::read("/etc/resolv.conf") {
        Ok(content) => frankenlibc_core::resolv::ResolverConfig::parse(&content),
        Err(_) => frankenlibc_core::resolv::ResolverConfig::default(),
    };

    let mut result = DnsResolution::default();
    let names =
        frankenlibc_core::resolv::dns::build_search_names(hostname, &config.search, config.ndots);

    for name in &names {
        for _attempt in 0..config.attempts {
            for ns in &config.nameservers {
                if want_v4
                    && result.ipv4.is_empty()
                    && let Some(records) = udp_dns_query(name, qtype::A, *ns, config.timeout)
                {
                    for rec in &records {
                        if let Some(v4) = rec.as_ipv4() {
                            result.ipv4.push(v4);
                        }
                    }
                }
                if want_v6
                    && result.ipv6.is_empty()
                    && let Some(records) = udp_dns_query(name, qtype::AAAA, *ns, config.timeout)
                {
                    for rec in &records {
                        if let Some(v6) = rec.as_ipv6() {
                            result.ipv6.push(v6);
                        }
                    }
                }
                if (!want_v4 || !result.ipv4.is_empty()) && (!want_v6 || !result.ipv6.is_empty()) {
                    return result;
                }
            }
        }
        if !result.ipv4.is_empty() || !result.ipv6.is_empty() {
            return result;
        }
    }
    result
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

    // SAFETY: getaddrinfo accepts optional C-string pointers; opt_cstr
    // validates tracked allocation bounds before producing a CStr view.
    let node_cstr = match unsafe { opt_cstr(node) } {
        Ok(value) => value,
        Err(()) => {
            record_resolver_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Bounds)),
            );
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, true);
            return libc::EAI_FAIL;
        }
    };
    // SAFETY: service follows the same optional C-string contract as node.
    let service_cstr = match unsafe { opt_cstr(service) } {
        Ok(value) => value,
        Err(()) => {
            record_resolver_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Bounds)),
            );
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, true);
            return libc::EAI_SERVICE;
        }
    };
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

    let flags = hints_ref.map(|h| h.ai_flags).unwrap_or(0);
    let family = hints_ref.map(|h| h.ai_family).unwrap_or(libc::AF_UNSPEC);
    let host_text = node_cstr.and_then(|c| c.to_str().ok());

    let mut nodes = Vec::new();
    let mut addrconfig_filter_eligible = host_text.is_none();

    match host_text {
        Some(text) => {
            let mut numeric_host = false;
            if let Ok(v4) = text.parse::<Ipv4Addr>() {
                numeric_host = true;
                nodes.push(unsafe { build_addrinfo_v4(v4, port, hints_ref) });
            } else if let Ok(v6) = text.parse::<Ipv6Addr>() {
                numeric_host = true;
                nodes.push(unsafe { build_addrinfo_v6(v6, port, hints_ref) });
            } else {
                // Check /etc/hosts for all matches (subset only)
                let content = read_hosts_backend().unwrap_or_default();
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
                // Use native DNS stub resolver.
                let want_v4 = family == libc::AF_UNSPEC || family == libc::AF_INET;
                let want_v6 = family == libc::AF_UNSPEC || family == libc::AF_INET6;
                let hostname_bytes = node_cstr.map(|c| c.to_bytes()).unwrap_or(b"");
                let dns_result = native_dns_resolve(hostname_bytes, want_v4, want_v6);

                for v4 in &dns_result.ipv4 {
                    if family == libc::AF_UNSPEC || family == libc::AF_INET {
                        nodes.push(unsafe { build_addrinfo_v4(*v4, port, hints_ref) });
                    }
                }
                for v6 in &dns_result.ipv6 {
                    if family == libc::AF_UNSPEC || family == libc::AF_INET6 {
                        nodes.push(unsafe { build_addrinfo_v6(*v6, port, hints_ref) });
                    }
                }

                if nodes.is_empty() {
                    if repair {
                        global_healing_policy().record(&HealingAction::ReturnSafeDefault);
                        nodes.push(unsafe {
                            build_addrinfo_v4(Ipv4Addr::LOCALHOST, port, hints_ref)
                        });
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

            addrconfig_filter_eligible = !numeric_host;
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

    if (flags & libc::AI_ADDRCONFIG) != 0
        && addrconfig_filter_eligible
        && let Some(state) = read_addrconfig_state_snapshot()
    {
        let unfiltered = nodes.len();
        let mut filtered = Vec::with_capacity(nodes.len());
        for node in nodes {
            if node.is_null() {
                filtered.push(node);
                continue;
            }
            // SAFETY: non-null nodes were allocated as libc::addrinfo-compatible records.
            if state.supports_family(unsafe { (*node).ai_family }) {
                filtered.push(node);
            } else {
                // SAFETY: filtered-out node is not returned to the caller.
                unsafe { free_addrinfo_node(node) };
            }
        }
        nodes = filtered;
        if nodes.is_empty() && unfiltered != 0 {
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

    if nodes.iter().any(|node| node.is_null()) {
        for node in nodes {
            // SAFETY: non-null nodes in this local vector are not returned after
            // the allocation failure path.
            unsafe { free_addrinfo_node(node) };
        }
        record_resolver_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Bounds)),
        );
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, true);
        return libc::EAI_MEMORY;
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

        let canon = unsafe { (*cur).ai_canonname };
        if !canon.is_null() {
            // Note: glibc contiguous allocations sometimes place canonname in the same block.
            // If it is NOT in the same block, we would leak it. However, our getaddrinfo
            // currently always leaves it null. If we were to populate it, we'd place it
            // contiguously as well, or use a known layout to free it.
            // We leave canonname un-freed as glibc freeaddrinfo natively frees only `cur`.
        }

        // SAFETY: node ownership belongs to caller of freeaddrinfo.
        unsafe { free_addrinfo_node(cur) };
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
///
/// Thin shim over `frankenlibc_core::resolv::messages::gai_strerror_text`.
/// The static `&str` from core is fed through a fixed CStr lookup table
/// (each known message is a `c"..."` literal compiled into rodata) so
/// the returned `*const c_char` is NUL-terminated and outlives the call.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gai_strerror(errcode: c_int) -> *const c_char {
    let text = frankenlibc_core::resolv::messages::gai_strerror_text(errcode);
    // Map the &str back to a NUL-terminated C literal for the FFI return.
    match text {
        "Success" => c"Success".as_ptr(),
        "Temporary failure in name resolution" => c"Temporary failure in name resolution".as_ptr(),
        "Invalid value for ai_flags" => c"Invalid value for ai_flags".as_ptr(),
        "Non-recoverable failure in name resolution" => {
            c"Non-recoverable failure in name resolution".as_ptr()
        }
        "ai_family not supported" => c"ai_family not supported".as_ptr(),
        "Name or service not known" => c"Name or service not known".as_ptr(),
        "Service not supported for socket type" => {
            c"Service not supported for socket type".as_ptr()
        }
        "Socket type not supported" => c"Socket type not supported".as_ptr(),
        "Argument buffer overflow" => c"Argument buffer overflow".as_ptr(),
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

// Parse a single line from /etc/protocols.
//
// Format: `<protocol-name> <number> [<alias>...]`
// parse_protocols_line moved to frankenlibc_core::resolv. Local callers
// use frankenlibc_core::resolv::parse_protocols_line directly.

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
    // SAFETY: gethostbyname requires a C-string name; opt_cstr rejects known
    // malloc-backed unterminated inputs before creating the view.
    let name_cstr = match unsafe { opt_cstr(name) } {
        Ok(value) => value,
        Err(()) => {
            // SAFETY: null h_errnop means only thread-local h_errno is updated.
            unsafe { set_h_errnop(ptr::null_mut(), NO_RECOVERY_ERRNO) };
            // SAFETY: updates ABI errno TLS for the current thread.
            unsafe { set_abi_errno(frankenlibc_core::errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 18, true);
            return ptr::null_mut();
        }
    };
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
    // SAFETY: gethostbyname_r has the same C-string name contract.
    let name_cstr = match unsafe { opt_cstr(name) } {
        Ok(value) => value,
        Err(()) => {
            // SAFETY: h_errnop is the optional caller-provided h_errno pointer.
            unsafe { set_h_errnop(h_errnop, NO_RECOVERY_ERRNO) };
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, true);
            return libc::EINVAL;
        }
    };
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
            // glibc parity: ERANGE ("buffer too small, try again with a
            // bigger one") must not clobber *h_errnop. Callers rely on
            // that invariant to distinguish a retry-with-bigger-buffer
            // condition from a real resolution failure.
            if code != libc::ERANGE {
                // SAFETY: optional h_errno pointer from caller.
                unsafe { set_h_errnop(h_errnop, NO_RECOVERY_ERRNO) };
            }
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
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Resolver,
        addr as usize,
        len as usize,
        true,
        addr.is_null(),
        0,
    );
    if !result.is_null() {
        unsafe { *result = ptr::null_mut() };
    }
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_h_errnop(h_errnop, NO_RECOVERY_ERRNO) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, true);
        return libc::EACCES;
    }

    if addr.is_null() || af != libc::AF_INET || (len as usize) < 4 || !tracked_region_fits(addr, 4)
    {
        unsafe { set_h_errnop(h_errnop, NO_RECOVERY_ERRNO) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 5, true);
        return libc::EINVAL;
    }

    let octets = unsafe { std::slice::from_raw_parts(addr as *const u8, 4) };
    let ip = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    let ip_str = ip.to_string();

    let content = match read_hosts_backend() {
        Ok(c) => c,
        Err(_) => {
            unsafe { set_h_errnop(h_errnop, HOST_NOT_FOUND_ERRNO) };
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
            return libc::ENOENT;
        }
    };

    let hostnames = frankenlibc_core::resolv::reverse_lookup_hosts(&content, ip_str.as_bytes());
    if hostnames.is_empty() {
        unsafe { set_h_errnop(h_errnop, HOST_NOT_FOUND_ERRNO) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
        return libc::ENOENT;
    }

    match unsafe { write_reentrant_hostent(&hostnames[0], ip, result_buf, buf, buflen, result) } {
        Ok(()) => {
            unsafe { set_h_errnop(h_errnop, 0) };
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, false);
            0
        }
        Err(code) => {
            // glibc parity: ERANGE must leave *h_errnop untouched so
            // callers can safely retry with a grown buffer.
            if code != libc::ERANGE {
                unsafe { set_h_errnop(h_errnop, NO_RECOVERY_ERRNO) };
            }
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 25, true);
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

    // Only support AF_INET for reverse lookup.
    if af != libc::AF_INET || (len as usize) < 4 {
        unsafe { set_h_errnop(ptr::null_mut(), HOST_NOT_FOUND_ERRNO) };
        return ptr::null_mut();
    }
    if !tracked_region_fits(addr, 4) {
        unsafe { set_h_errnop(ptr::null_mut(), NO_RECOVERY_ERRNO) };
        return ptr::null_mut();
    }

    // Read the IPv4 address
    let octets = unsafe { std::slice::from_raw_parts(addr as *const u8, 4) };
    let ip = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    let ip_str = ip.to_string();

    // Look up in /etc/hosts
    let content = match read_hosts_backend() {
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

    // SAFETY: name is non-null and follows getservbyname's C-string contract;
    // known_remaining bounds tracked malloc-backed inputs.
    let (name_len, name_terminated) =
        unsafe { crate::util::scan_c_string(name, known_remaining(name as usize)) };
    if !name_terminated {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 5, true);
        return ptr::null_mut();
    }
    let name_bytes = unsafe { std::slice::from_raw_parts(name as *const u8, name_len) };

    let proto_filter = if proto.is_null() {
        None
    } else {
        // SAFETY: proto is non-null in this branch and has getservbyname's
        // optional C-string contract.
        let (proto_len, proto_terminated) =
            unsafe { crate::util::scan_c_string(proto, known_remaining(proto as usize)) };
        if !proto_terminated {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 5, true);
            return ptr::null_mut();
        }
        Some(unsafe { std::slice::from_raw_parts(proto as *const u8, proto_len) })
    };

    let content = match read_services_backend() {
        Ok(c) => c,
        Err(_) => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
            return ptr::null_mut();
        }
    };

    // Use core parser to find the service
    let port = match frankenlibc_core::resolv::lookup_service(&content, name_bytes, proto_filter) {
        Some(p) => p,
        None => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
            return ptr::null_mut();
        }
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
                if entry.port == port
                    && (entry.name.eq_ignore_ascii_case(name_bytes)
                        || entry
                            .aliases
                            .iter()
                            .any(|alias| alias.eq_ignore_ascii_case(name_bytes)))
                {
                    Some(entry.protocol)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| b"tcp".to_vec())
    };

    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 20, false);
    SERVENT_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        copy_to_cchar_buf(&mut storage.name, name_bytes);
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

    // SAFETY: proto is optional; opt_cstr returns None for null and rejects
    // known unterminated storage before any bytes are borrowed.
    let proto_filter = match unsafe { opt_cstr(proto) } {
        Ok(value) => value.map(CStr::to_bytes),
        Err(()) => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 5, true);
            return ptr::null_mut();
        }
    };

    let content = match read_services_backend() {
        Ok(c) => c,
        Err(_) => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
            return ptr::null_mut();
        }
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
        None => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
            return ptr::null_mut();
        }
    };

    // Success path: record service lookup completed
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 20, false);

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

    // SAFETY: name is non-null and follows getprotobyname's C-string contract;
    // known_remaining bounds tracked malloc-backed inputs.
    let (name_len, name_terminated) =
        unsafe { crate::util::scan_c_string(name, known_remaining(name as usize)) };
    if !name_terminated {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 5, true);
        return ptr::null_mut();
    }
    let name_bytes = unsafe { std::slice::from_raw_parts(name as *const u8, name_len) };

    let content = match std::fs::read("/etc/protocols") {
        Ok(c) => c,
        Err(_) => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
            return ptr::null_mut();
        }
    };

    let entry = match frankenlibc_core::resolv::lookup_protocol_by_name(&content, name_bytes) {
        Some(e) => e,
        None => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
            return ptr::null_mut();
        }
    };

    // Success path: record protocol lookup completed
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 20, false);

    PROTOENT_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        copy_to_cchar_buf(&mut storage.name, &entry.name);
        storage.aliases[0] = ptr::null_mut();
        storage.protoent = libc::protoent {
            p_name: storage.name.as_mut_ptr(),
            p_aliases: storage.aliases.as_mut_ptr(),
            p_proto: entry.number,
        };
        (&mut storage.protoent as *mut libc::protoent).cast::<c_void>()
    })
}

/// POSIX `getprotobynumber` — look up a protocol by number in /etc/protocols.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobynumber(proto: c_int) -> *mut c_void {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Resolver,
        0, // no pointer argument
        0,
        false, // read-only lookup
        true,  // no pointer to validate
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    let content = match std::fs::read("/etc/protocols") {
        Ok(c) => c,
        Err(_) => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
            return ptr::null_mut();
        }
    };

    let entry = match frankenlibc_core::resolv::lookup_protocol_by_number(&content, proto) {
        Some(e) => e,
        None => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
            return ptr::null_mut();
        }
    };

    // Success path: record protocol lookup completed
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 20, false);

    PROTOENT_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        copy_to_cchar_buf(&mut storage.name, &entry.name);
        storage.aliases[0] = ptr::null_mut();
        storage.protoent = libc::protoent {
            p_name: storage.name.as_mut_ptr(),
            p_aliases: storage.aliases.as_mut_ptr(),
            p_proto: entry.number,
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

// gai_cancel/gai_error/gai_suspend are defined in unistd_abi.rs

// ===========================================================================
// libresolv ns_* helpers — byte read/write + name comparators + canon
// ===========================================================================
//
// These are the small parsing primitives BIND/libresolv expose under
// `<arpa/nameser.h>`. Programs that link against libresolv.so.2 (or
// LD_PRELOAD frankenlibc) can resolve them here. The high-level
// resolver (getaddrinfo, gethostbyname, etc.) lives above; these are
// the low-level helpers it builds on.

/// libresolv `ns_get16(*src) -> u16` — read a big-endian 16-bit
/// unsigned integer from the 2 bytes pointed to by `src`.
///
/// # Safety
///
/// `src` must point to at least 2 readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_get16(src: *const u8) -> libc::c_uint {
    if src.is_null() || !tracked_region_fits(src.cast(), 2) {
        return 0;
    }
    // SAFETY: caller-supplied 2-byte buffer. Return type is c_uint (u32) to
    // match glibc's `unsigned int ns_get16(...)` ABI exactly — the return
    // value occupies the full 32-bit register slot, not just the low 16
    // bits, so glibc-compiled callers don't read garbage in the upper half.
    let b0 = unsafe { *src };
    let b1 = unsafe { *src.add(1) };
    (((b0 as u16) << 8) | (b1 as u16)) as libc::c_uint
}

/// libresolv `ns_get32(*src) -> u32` — read a big-endian 32-bit
/// unsigned integer from the 4 bytes pointed to by `src`.
///
/// # Safety
///
/// `src` must point to at least 4 readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_get32(src: *const u8) -> libc::c_ulong {
    if src.is_null() || !tracked_region_fits(src.cast(), 4) {
        return 0;
    }
    // SAFETY: caller-supplied 4-byte buffer. Return type is c_ulong (u64
    // on Linux/x86_64) to match glibc's `unsigned long ns_get32(...)` ABI.
    // The value never exceeds u32::MAX (4 bytes of data), but the SysV AMD64
    // calling convention requires the full 64-bit register slot for u_long
    // returns.
    let bytes = unsafe { core::slice::from_raw_parts(src, 4) };
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as libc::c_ulong
}

/// libresolv `ns_put16(value, *dst)` — write `value` as a big-endian
/// 16-bit unsigned integer to the 2 bytes at `dst`.
///
/// # Safety
///
/// `dst` must point to at least 2 writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_put16(value: u16, dst: *mut u8) {
    if dst.is_null() || !tracked_region_fits(dst.cast(), 2) {
        return;
    }
    // SAFETY: caller-supplied 2-byte buffer.
    unsafe {
        *dst = (value >> 8) as u8;
        *dst.add(1) = value as u8;
    }
}

/// libresolv `ns_put32(value, *dst)` — write `value` as a big-endian
/// 32-bit unsigned integer to the 4 bytes at `dst`.
///
/// # Safety
///
/// `dst` must point to at least 4 writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_put32(value: u32, dst: *mut u8) {
    if dst.is_null() || !tracked_region_fits(dst.cast(), 4) {
        return;
    }
    let bytes = value.to_be_bytes();
    // SAFETY: caller-supplied 4-byte buffer.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, 4) };
}

// --- name helpers ---

/// Strip an optional single trailing dot for comparison purposes.
fn strip_trailing_dot(s: &[u8]) -> &[u8] {
    if let Some(&b'.') = s.last() {
        &s[..s.len() - 1]
    } else {
        s
    }
}

/// Lowercase a single byte for case-insensitive ASCII compare. DNS
/// names are case-insensitive in the ASCII range; non-ASCII bytes are
/// compared byte-for-byte.
#[inline]
fn dns_lower(c: u8) -> u8 {
    if c.is_ascii_uppercase() { c | 0x20 } else { c }
}

fn names_eq_no_case_no_dot(a: &[u8], b: &[u8]) -> bool {
    let a = strip_trailing_dot(a);
    let b = strip_trailing_dot(b);
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| dns_lower(*x) == dns_lower(*y))
}

/// libresolv `ns_samename(a, b) -> int` — case-insensitively compare
/// two DNS names. Returns 1 if same, 0 if different, -1 on error
/// (NULL inputs).
///
/// Trailing dots are tolerated: `"foo.com"` and `"foo.com."` compare
/// equal.
///
/// # Safety
///
/// `a` and `b`, when non-NULL, must be NUL-terminated C strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_samename(a: *const c_char, b: *const c_char) -> c_int {
    let Some(abytes) = (unsafe { required_cstr_bytes(a) }) else {
        return -1;
    };
    let Some(bbytes) = (unsafe { required_cstr_bytes(b) }) else {
        return -1;
    };
    if names_eq_no_case_no_dot(abytes, bbytes) {
        1
    } else {
        0
    }
}

/// libresolv `ns_samedomain(a, b) -> int` — return 1 if `a` is in
/// (or equal to) domain `b`. The empty string `""` and the root
/// label `"."` are the root domain: every other name is in them.
/// Otherwise, `a` is in `b` when stripping the leading
/// `len(a) - len(b) - 1` characters of `a` (plus a separator dot)
/// yields exactly `b`.
///
/// Returns 0 if `a` is not in `b`. Trailing dots are tolerated for
/// either argument.
///
/// # Safety
///
/// `a` and `b`, when non-NULL, must be NUL-terminated C strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_samedomain(a: *const c_char, b: *const c_char) -> c_int {
    let Some(abytes) = (unsafe { required_cstr_bytes(a) }) else {
        return 0;
    };
    let Some(bbytes) = (unsafe { required_cstr_bytes(b) }) else {
        return 0;
    };
    let a = strip_trailing_dot(abytes);
    let b = strip_trailing_dot(bbytes);
    if b.is_empty() {
        return 1;
    }
    if a.len() == b.len() {
        return if names_eq_no_case_no_dot(a, b) { 1 } else { 0 };
    }
    if a.len() < b.len() + 1 {
        return 0;
    }
    let split = a.len() - b.len() - 1;
    if a[split] != b'.' {
        return 0;
    }
    if names_eq_no_case_no_dot(&a[split + 1..], b) {
        1
    } else {
        0
    }
}

/// libresolv `ns_subdomain(a, b) -> int` — return 1 if `a` is a
/// PROPER subdomain of `b` (i.e., `samedomain(a, b) && !samename(a,
/// b)`). Returns 0 otherwise.
///
/// # Safety
///
/// `a` and `b`, when non-NULL, must be NUL-terminated C strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_subdomain(a: *const c_char, b: *const c_char) -> c_int {
    let same_dom = unsafe { ns_samedomain(a, b) };
    if same_dom != 1 {
        return 0;
    }
    let same_name = unsafe { ns_samename(a, b) };
    if same_name == 1 { 0 } else { 1 }
}

/// libresolv `ns_makecanon(src, dst, dstsiz) -> int` — copy `src` to
/// `dst`, ensuring the result is NUL-terminated and ends with a
/// trailing dot (the canonical form). Returns 0 on success, or -1
/// with errno set to `EMSGSIZE` if `dst` is too small (or `EINVAL`
/// if either pointer is NULL).
///
/// If `src` already ends with a dot it is copied verbatim; otherwise
/// a `.` is appended.
///
/// # Safety
///
/// `src` must be a NUL-terminated C string. `dst` must point to at
/// least `dstsiz` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_makecanon(
    src: *const c_char,
    dst: *mut c_char,
    dstsiz: usize,
) -> c_int {
    let Some(sbytes) = (unsafe { required_cstr_bytes(src) }) else {
        unsafe { set_abi_errno(frankenlibc_core::errno::EINVAL) };
        return -1;
    };
    if dst.is_null() {
        unsafe { set_abi_errno(frankenlibc_core::errno::EINVAL) };
        return -1;
    }
    let needs_dot = sbytes.last().copied() != Some(b'.');
    let extra: usize = if needs_dot { 1 } else { 0 };
    let needed = sbytes.len().saturating_add(extra).saturating_add(1);
    if needed > dstsiz {
        unsafe { set_abi_errno(libc::EMSGSIZE) };
        return -1;
    }
    // SAFETY: dst points to dstsiz writable bytes; we write needed ≤ dstsiz.
    unsafe {
        core::ptr::copy_nonoverlapping(sbytes.as_ptr() as *const c_char, dst, sbytes.len());
        let mut off = sbytes.len();
        if needs_dot {
            *dst.add(off) = b'.' as c_char;
            off += 1;
        }
        *dst.add(off) = 0;
    }
    0
}

// ===========================================================================
// libresolv ns_parse_ttl / ns_format_ttl / ns_datetosecs
// ===========================================================================

/// libresolv `ns_parse_ttl(src, *dst) -> int` — parse a DNS TTL
/// string. Grammar (case-insensitive): `(number unit?)+` where
/// `unit` is one of `W`, `D`, `H`, `M`, `S` and a missing trailing
/// unit defaults to seconds. Multipliers: W=604800, D=86400,
/// H=3600, M=60, S=1.
///
/// Returns 0 on success and writes the total seconds to `*dst`;
/// returns -1 on syntax error or u32 overflow.
///
/// # Safety
///
/// `src` must be a NUL-terminated C string. `dst`, when non-NULL,
/// must point to writable `u32` storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_parse_ttl(src: *const c_char, dst: *mut u32) -> c_int {
    let Some(bytes) = (unsafe { required_cstr_bytes(src) }) else {
        return -1;
    };
    let mut total: u32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let mut tmp: u32 = 0;
        let mut digits = 0;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            // overflow check on the per-component accumulator
            let next = tmp
                .checked_mul(10)
                .and_then(|n| n.checked_add((bytes[i] - b'0') as u32));
            tmp = match next {
                Some(v) => v,
                None => return -1,
            };
            digits += 1;
            if digits > 10 {
                return -1;
            }
            i += 1;
        }
        if digits == 0 {
            return -1;
        }
        let mul: u32 = if i >= bytes.len() {
            1 // missing trailing unit = seconds
        } else {
            match bytes[i] {
                b'w' | b'W' => {
                    i += 1;
                    604_800
                }
                b'd' | b'D' => {
                    i += 1;
                    86_400
                }
                b'h' | b'H' => {
                    i += 1;
                    3_600
                }
                b'm' | b'M' => {
                    i += 1;
                    60
                }
                b's' | b'S' => {
                    i += 1;
                    1
                }
                _ => return -1,
            }
        };
        let component = match tmp.checked_mul(mul) {
            Some(v) => v,
            None => return -1,
        };
        total = match total.checked_add(component) {
            Some(v) => v,
            None => return -1,
        };
    }
    if !dst.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *dst = total };
    }
    0
}

#[inline]
fn ttl_emit_unit(value: u64, unit: u8, dst: &mut [u8], pos: &mut usize) -> bool {
    // Format value in decimal then append unit. Returns false on overflow.
    // u64 is wide enough for any TTL value glibc accepts (u_long).
    let mut digits = [0u8; 20];
    let mut n = value;
    let mut len = 0usize;
    if n == 0 {
        digits[0] = b'0';
        len = 1;
    } else {
        while n > 0 {
            digits[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
    }
    if *pos + len + 1 > dst.len() {
        return false;
    }
    for i in 0..len {
        dst[*pos + i] = digits[len - 1 - i];
    }
    dst[*pos + len] = unit;
    *pos += len + 1;
    true
}

/// libresolv `ns_format_ttl(src, dst, dstlen) -> int` — format
/// `src` (a TTL in seconds) as a C string at `dst` of capacity
/// `dstlen`. Greedy decomposition into weeks (`W`), days (`D`),
/// hours (`H`), minutes (`M`), seconds (`S`). When more than one
/// unit is present the result is lowercase; with a single unit it
/// is uppercase, matching BIND9's libresolv reference. The output
/// is NUL-terminated.
///
/// Returns the number of characters written (excluding the
/// terminating NUL) on success, or -1 on overflow.
///
/// # Safety
///
/// `dst`, when non-NULL, must point to at least `dstlen` writable
/// bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_format_ttl(
    src: libc::c_ulong,
    dst: *mut c_char,
    dstlen: usize,
) -> c_int {
    if dst.is_null() || dstlen == 0 {
        return -1;
    }
    // Match glibc: u_long input, decomposed across u64 to avoid truncation
    // for values > u32::MAX. Since `src` is unsigned, modular arithmetic is
    // exact at every cascade level. On Linux x86_64 c_ulong is u64; the
    // explicit widen keeps 32-bit portability.
    #[allow(clippy::useless_conversion)]
    let mut s: u64 = u64::try_from(src).unwrap_or(u64::MAX);
    let secs = s % 60;
    s /= 60;
    let mins = s % 60;
    s /= 60;
    let hours = s % 24;
    s /= 24;
    let days = s % 7;
    s /= 7;
    let weeks = s;

    // Need NUL-terminator slot; reserve one.
    let mut buf = vec![0u8; dstlen];
    let mut pos = 0usize;
    let mut units = 0;
    if weeks != 0 && ttl_emit_unit(weeks, b'W', &mut buf, &mut pos) {
        units += 1;
    } else if weeks != 0 {
        return -1;
    }
    if days != 0 && ttl_emit_unit(days, b'D', &mut buf, &mut pos) {
        units += 1;
    } else if days != 0 {
        return -1;
    }
    if hours != 0 && ttl_emit_unit(hours, b'H', &mut buf, &mut pos) {
        units += 1;
    } else if hours != 0 {
        return -1;
    }
    if mins != 0 && ttl_emit_unit(mins, b'M', &mut buf, &mut pos) {
        units += 1;
    } else if mins != 0 {
        return -1;
    }
    let any_higher = weeks != 0 || days != 0 || hours != 0 || mins != 0;
    if secs != 0 || !any_higher {
        if !ttl_emit_unit(secs, b'S', &mut buf, &mut pos) {
            return -1;
        }
        units += 1;
    }

    if pos + 1 > dstlen {
        return -1;
    }

    // Multi-unit results are lowercased per the BIND reference.
    if units > 1 {
        for b in buf.iter_mut().take(pos) {
            if b.is_ascii_uppercase() {
                *b = b.to_ascii_lowercase();
            }
        }
    }

    // SAFETY: dst points to dstlen writable bytes; we wrote `pos` <= dstlen-1.
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr() as *const c_char, dst, pos);
        *dst.add(pos) = 0;
    }
    pos as c_int
}

#[inline]
fn ns_date_is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[inline]
fn ns_date_days_in_month(year: i32, month: i32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if ns_date_is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn ns_date_to_epoch_u32(
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
    second: i32,
) -> Option<u32> {
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=ns_date_days_in_month(year, month) as i32).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }

    let mut days = 0u64;
    for y in 1970..year {
        days += if ns_date_is_leap_year(y) { 366 } else { 365 };
    }
    for m in 1..month {
        days += ns_date_days_in_month(year, m) as u64;
    }
    days += (day - 1) as u64;

    let day_seconds = (hour as u64)
        .checked_mul(3_600)?
        .checked_add((minute as u64).checked_mul(60)?)?
        .checked_add(second as u64)?;
    let total = days.checked_mul(86_400)?.checked_add(day_seconds)?;
    u32::try_from(total).ok()
}

/// libresolv `ns_datetosecs(cp, *errp) -> u32` — parse a 14-char
/// `"YYYYMMDDHHMMSS"` UTC date string into seconds since epoch.
/// Sets `*errp = 1` on parse error and returns 0; otherwise sets
/// `*errp = 0` and returns the second count.
///
/// # Safety
///
/// `cp` must be a NUL-terminated C string. `errp`, when non-NULL,
/// must point to writable `c_int` storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_datetosecs(cp: *const c_char, errp: *mut c_int) -> u32 {
    let set_err = |val: c_int| {
        if !errp.is_null() {
            // SAFETY: caller-supplied writable slot.
            unsafe { *errp = val };
        }
    };
    let Some(s) = (unsafe { required_cstr_bytes(cp) }) else {
        set_err(1);
        return 0;
    };
    if s.len() != 14 || !s.iter().all(u8::is_ascii_digit) {
        set_err(1);
        return 0;
    }
    let to_n = |range: core::ops::Range<usize>| -> i32 {
        let mut v: i32 = 0;
        for &b in &s[range] {
            v = v * 10 + (b - b'0') as i32;
        }
        v
    };
    let year = to_n(0..4);
    let month = to_n(4..6);
    let day = to_n(6..8);
    let hour = to_n(8..10);
    let minute = to_n(10..12);
    let second = to_n(12..14);

    match ns_date_to_epoch_u32(year, month, day, hour, minute, second) {
        Some(secs) => {
            set_err(0);
            secs
        }
        None => {
            set_err(1);
            0
        }
    }
}

// ===========================================================================
// Deprecated res_-prefixed front-ends + res_send hook setters + ns_name_*
// ===========================================================================

/// libresolv `res_gethostbyname(name)` — historical front-end alias
/// for `gethostbyname`. Defined here so binaries that link against
/// the old BIND symbol resolve cleanly.
///
/// # Safety
///
/// `name`, when non-NULL, must be a NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_gethostbyname(name: *const c_char) -> *mut c_void {
    unsafe { gethostbyname(name) }
}

/// libresolv `res_gethostbyname2(name, af)` — historical front-end
/// alias for `gethostbyname2`.
///
/// # Safety
///
/// `name`, when non-NULL, must be a NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_gethostbyname2(name: *const c_char, af: c_int) -> *mut c_void {
    unsafe { crate::unistd_abi::gethostbyname2(name, af) }
}

/// libresolv `res_gethostbyaddr(addr, len, type)` — historical
/// front-end alias for `gethostbyaddr`.
///
/// # Safety
///
/// `addr`, when non-NULL, must point to at least `len` readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_gethostbyaddr(
    addr: *const c_void,
    len: u32,
    addr_type: c_int,
) -> *mut c_void {
    unsafe { gethostbyaddr(addr, len, addr_type) }
}

// ----- res_send hooks (optional pre-query / post-response callbacks) -----
//
// The exact pointee types in glibc are deprecated `enum res_sendhookact`
// returning function pointers. We model them as opaque `*mut c_void` since
// we don't invoke them internally (no pluggable resolver core), but we
// store them per-thread for any caller that registers and re-reads them
// (some test harnesses do exactly this).

std::thread_local! {
    static RES_QHOOK: std::cell::Cell<*mut c_void> = const { std::cell::Cell::new(core::ptr::null_mut()) };
    static RES_RHOOK: std::cell::Cell<*mut c_void> = const { std::cell::Cell::new(core::ptr::null_mut()) };
}

/// Test/inspection accessor for the most recently installed query hook.
#[doc(hidden)]
pub fn res_send_qhook_for_tests() -> *mut c_void {
    RES_QHOOK.with(|c| c.get())
}

/// Test/inspection accessor for the most recently installed response hook.
#[doc(hidden)]
pub fn res_send_rhook_for_tests() -> *mut c_void {
    RES_RHOOK.with(|c| c.get())
}

/// libresolv `res_send_setqhook(qhook)` — install a pre-query
/// callback. Stored per-thread; not invoked internally (we have no
/// pluggable resolver core). Provided so binaries that register a
/// hook don't fail at link time.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_send_setqhook(qhook: *mut c_void) {
    RES_QHOOK.with(|c| c.set(qhook));
}

/// libresolv `res_send_setrhook(rhook)` — install a post-response
/// callback. Stored per-thread; not invoked internally.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_send_setrhook(rhook: *mut c_void) {
    RES_RHOOK.with(|c| c.set(rhook));
}

// ----- ns_name_ntol / ns_name_rollback -----

/// libresolv `ns_name_ntol(src, dst, dstsiz) -> int` — convert a
/// wire-format DNS domain name to lowercase. Wire format is a
/// sequence of length-prefixed labels terminated by a 0-length byte.
/// The total encoded length cannot exceed 255 bytes.
///
/// Returns 0 on success and writes the lowered copy to `dst`.
/// Returns -1 if `dst` is too small or the encoded name is malformed
/// (label too long, no terminator within 255 bytes).
///
/// # Safety
///
/// `src` must point to a wire-format name (length-prefixed labels
/// terminated by a 0 length byte) of total length ≤ 255 bytes.
/// `dst` must point to at least `dstsiz` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_ntol(src: *const u8, dst: *mut u8, dstsiz: usize) -> c_int {
    if src.is_null() || dst.is_null() {
        return -1;
    }
    let mut total = 0usize;
    loop {
        if total >= 256 {
            return -1;
        }
        // SAFETY: caller-supplied wire-format name; we cap traversal at 256.
        let len = unsafe { *src.add(total) };
        if total >= dstsiz {
            return -1;
        }
        // Lowercase ASCII letters in the LABEL bytes; the length byte
        // itself is copied verbatim.
        // SAFETY: dst has dstsiz bytes; we verified total < dstsiz.
        unsafe { *dst.add(total) = len };
        total += 1;
        if len == 0 {
            return 0;
        }
        if len > 63 {
            // Compression pointer (top two bits set) or invalid label.
            // The Itanium nameserver lib treats compression as a copy
            // of the remainder, but lowercase only labels we can see.
            // For simplicity, refuse compressed names.
            if len & 0xC0 == 0xC0 {
                if total >= dstsiz {
                    return -1;
                }
                // Copy the second pointer byte verbatim.
                // SAFETY: caller-supplied 256-byte cap on input.
                unsafe { *dst.add(total) = *src.add(total) };
                return 0;
            }
            return -1;
        }
        if total + (len as usize) > dstsiz {
            return -1;
        }
        for _ in 0..len {
            // SAFETY: bounded by total + len ≤ dstsiz.
            let b = unsafe { *src.add(total) };
            let lowered = if b.is_ascii_uppercase() { b | 0x20 } else { b };
            unsafe { *dst.add(total) = lowered };
            total += 1;
        }
    }
}

/// libresolv `ns_name_rollback(srcp, dnptrs, lastdnptr)` — undo
/// partial name compression entries left in `dnptrs` by
/// `ns_name_pack` (or its callers) when an error aborts the
/// in-progress name. Walks `dnptrs[]` from the end backwards and
/// clears any entry whose pointer value is at or past `srcp`.
///
/// `dnptrs` is a NULL-terminated array. `lastdnptr` is one past the
/// end of the usable slots.
///
/// # Safety
///
/// `dnptrs`, when non-NULL, must point to a NULL-terminated array of
/// `*const u8`. `lastdnptr`, when non-NULL, must be valid as a
/// boundary pointer for that array.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_rollback(
    srcp: *const u8,
    dnptrs: *mut *mut u8,
    lastdnptr: *mut *mut u8,
) {
    if dnptrs.is_null() {
        return;
    }
    // Walk forward from dnptrs[0] until NULL terminator or lastdnptr.
    let mut i: isize = 0;
    loop {
        // SAFETY: caller-supplied array.
        let slot = unsafe { dnptrs.offset(i) };
        if !lastdnptr.is_null() && slot >= lastdnptr {
            break;
        }
        let entry = unsafe { *slot };
        if entry.is_null() {
            break;
        }
        if (entry as usize) >= (srcp as usize) {
            // Clear this slot and shift remaining valid slots left.
            // SAFETY: we own this slot.
            unsafe { *slot = core::ptr::null_mut() };
            // Stop on first removed slot — subsequent entries are by
            // contract also at-or-past srcp because they were appended
            // later, but to mirror BIND9 we just truncate here.
            break;
        }
        i += 1;
    }
}

// ===========================================================================
// libresolv DNS message parser — ns_initparse / ns_parserr / ns_skiprr /
// ns_msg_getflag
// ===========================================================================
//
// Layout matches glibc's `<arpa/nameser.h>` exactly so callers can pass
// the same `ns_msg` / `ns_rr` storage between our resolv_abi and any
// other libresolv-shaped code.

const NS_HFIXEDSZ: usize = 12;
const NS_QFIXEDSZ: usize = 4;
const NS_RRFIXEDSZ: usize = 10;
const NS_MAXDNAME: usize = 1025;
const NS_S_MAX: usize = 4;

/// C-compatible `ns_msg`. Layout (offsets in bytes):
///   0:  _msg            8
///   8:  _eom            8
///   16: _id             2
///   18: _flags          2
///   20: _counts[4]      8
///   28: padding         4
///   32: _sections[4]    32
///   64: _sect           4
///   68: _rrnum          4
///   72: _msg_ptr        8
/// Total: 80 bytes.
#[repr(C)]
pub struct CNsMsg {
    pub _msg: *const u8,
    pub _eom: *const u8,
    pub _id: u16,
    pub _flags: u16,
    pub _counts: [u16; NS_S_MAX],
    pub _sections: [*const u8; NS_S_MAX],
    pub _sect: c_int,
    pub _rrnum: c_int,
    pub _msg_ptr: *const u8,
}

/// C-compatible `ns_rr`. Layout (offsets in bytes):
///   0:    name[1025]
///   1026: type      (after 1-byte alignment pad)
///   1028: rr_class
///   1030: ttl
///   1034: rdlength
///   1040: rdata     (8-byte aligned)
/// Total: 1048 bytes.
#[repr(C)]
pub struct CNsRr {
    pub name: [c_char; NS_MAXDNAME],
    pub _type: u16,
    pub rr_class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: *const u8,
}

#[inline]
fn read_be_u16_at(buf: &[u8], pos: usize) -> Option<u16> {
    if pos + 2 > buf.len() {
        return None;
    }
    Some(u16::from_be_bytes([buf[pos], buf[pos + 1]]))
}

#[inline]
fn read_be_u32_at(buf: &[u8], pos: usize) -> Option<u32> {
    if pos + 4 > buf.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        buf[pos],
        buf[pos + 1],
        buf[pos + 2],
        buf[pos + 3],
    ]))
}

unsafe fn ns_skip_one_rr(
    msg_buf: &[u8],
    eom: *const u8,
    pos: usize,
    section: c_int,
) -> Option<usize> {
    // SAFETY: msg_buf is the linear msg slice; eom is its end pointer.
    let comp = unsafe { msg_buf.as_ptr().add(pos) };
    let n = unsafe { crate::unistd_abi::dn_skipname(comp, eom) };
    if n < 0 {
        return None;
    }
    let mut p = pos.checked_add(n as usize)?;
    if section == 0 {
        // Question: name + qtype(2) + qclass(2)
        p = p.checked_add(NS_QFIXEDSZ)?;
        if p > msg_buf.len() {
            return None;
        }
    } else {
        // Answer / Authority / Additional: name + 10 + rdlength bytes
        let rdlen = read_be_u16_at(msg_buf, p + 8)?;
        p = p.checked_add(NS_RRFIXEDSZ)?.checked_add(rdlen as usize)?;
        if p > msg_buf.len() {
            return None;
        }
    }
    Some(p)
}

/// libresolv `ns_initparse(msg, msglen, *handle) -> int` — parse a
/// DNS message header and walk each of the 4 sections (qd / an / ns /
/// ar) to find their boundaries. The result populates the
/// caller-supplied [`CNsMsg`] handle so subsequent
/// [`ns_parserr`] / [`ns_msg_getflag`] calls can index into it.
///
/// Returns 0 on success, -1 on a malformed message (header too short,
/// section walk overruns the message, etc.).
///
/// # Safety
///
/// `msg` must point to at least `msglen` readable bytes. `handle`
/// must point to writable [`CNsMsg`] storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_initparse(msg: *const u8, msglen: c_int, handle: *mut CNsMsg) -> c_int {
    if msg.is_null() || handle.is_null() || msglen < 0 {
        return -1;
    }
    let msglen = msglen as usize;
    if msglen < NS_HFIXEDSZ {
        return -1;
    }
    // SAFETY: caller-supplied buffer of msglen bytes.
    let buf = unsafe { core::slice::from_raw_parts(msg, msglen) };
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let counts: [u16; NS_S_MAX] = [
        u16::from_be_bytes([buf[4], buf[5]]),
        u16::from_be_bytes([buf[6], buf[7]]),
        u16::from_be_bytes([buf[8], buf[9]]),
        u16::from_be_bytes([buf[10], buf[11]]),
    ];

    // Walk each section to find boundaries.
    let eom = unsafe { msg.add(msglen) };
    let mut sections: [*const u8; NS_S_MAX] = [core::ptr::null(); NS_S_MAX];
    let mut pos = NS_HFIXEDSZ;
    for section in 0..NS_S_MAX {
        // SAFETY: msg + pos is within [msg, eom] by construction below.
        sections[section] = unsafe { msg.add(pos) };
        for _ in 0..counts[section] {
            let new_pos = match unsafe { ns_skip_one_rr(buf, eom, pos, section as c_int) } {
                Some(p) => p,
                None => return -1,
            };
            pos = new_pos;
        }
    }

    // SAFETY: caller-supplied writable handle.
    unsafe {
        (*handle)._msg = msg;
        (*handle)._eom = eom;
        (*handle)._id = id;
        (*handle)._flags = flags;
        (*handle)._counts = counts;
        (*handle)._sections = sections;
        (*handle)._sect = 0;
        (*handle)._rrnum = 0;
        (*handle)._msg_ptr = sections[0];
    }
    0
}

/// libresolv `ns_skiprr(ptr, eom, section, count) -> int` — skip
/// `count` resource records starting at `ptr` and return the number
/// of bytes consumed. Returns -1 on malformed input.
///
/// # Safety
///
/// `ptr` and `eom` must bound a contiguous DNS message buffer with
/// `ptr <= eom`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_skiprr(
    ptr: *const u8,
    eom: *const u8,
    section: c_int,
    count: c_int,
) -> c_int {
    if ptr.is_null() || eom.is_null() || count < 0 || ptr > eom {
        return -1;
    }
    let len = unsafe { eom.offset_from(ptr) } as usize;
    let buf = unsafe { core::slice::from_raw_parts(ptr, len) };
    let mut pos = 0usize;
    for _ in 0..count {
        match unsafe { ns_skip_one_rr(buf, eom, pos, section) } {
            Some(p) => pos = p,
            None => return -1,
        }
    }
    pos as c_int
}

/// libresolv `ns_parserr(*handle, section, rrnum, *rr) -> int` —
/// fetch the `rrnum`-th resource record in the given `section` and
/// fill the caller's [`CNsRr`].
///
/// Walks from the section start each call (no incremental cursor
/// caching). Returns 0 on success, -1 on bounds error or malformed
/// message.
///
/// # Safety
///
/// `handle` must be a [`CNsMsg`] previously initialized by
/// [`ns_initparse`]. `rr` must point to writable [`CNsRr`] storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_parserr(
    handle: *mut CNsMsg,
    section: c_int,
    rrnum: c_int,
    rr: *mut CNsRr,
) -> c_int {
    if handle.is_null() || rr.is_null() || rrnum < 0 {
        return -1;
    }
    if !(0..NS_S_MAX as c_int).contains(&section) {
        return -1;
    }
    // SAFETY: caller-supplied initialized handle.
    let msg_ptr = unsafe { (*handle)._msg };
    let eom = unsafe { (*handle)._eom };
    let count = unsafe { (*handle)._counts[section as usize] };
    let section_start = unsafe { (*handle)._sections[section as usize] };
    if (rrnum as u16) >= count {
        return -1;
    }
    if msg_ptr.is_null() || eom.is_null() || section_start.is_null() {
        return -1;
    }
    let msg_len = unsafe { eom.offset_from(msg_ptr) } as usize;
    let buf = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len) };
    let mut pos = unsafe { section_start.offset_from(msg_ptr) } as usize;
    for _ in 0..rrnum {
        match unsafe { ns_skip_one_rr(buf, eom, pos, section) } {
            Some(p) => pos = p,
            None => return -1,
        }
    }

    // Expand the name into the rr.name field.
    let comp = unsafe { msg_ptr.add(pos) };
    let name_buf = unsafe { (*rr).name.as_mut_ptr() };
    let name_len =
        unsafe { crate::unistd_abi::dn_expand(msg_ptr, eom, comp, name_buf, NS_MAXDNAME as c_int) };
    if name_len < 0 {
        return -1;
    }
    pos = pos.saturating_add(name_len as usize);

    if section == 0 {
        // Question: just type + class.
        let qtype = match read_be_u16_at(buf, pos) {
            Some(v) => v,
            None => return -1,
        };
        let qclass = match read_be_u16_at(buf, pos + 2) {
            Some(v) => v,
            None => return -1,
        };
        // SAFETY: writable caller-supplied CNsRr.
        unsafe {
            (*rr)._type = qtype;
            (*rr).rr_class = qclass;
            (*rr).ttl = 0;
            (*rr).rdlength = 0;
            (*rr).rdata = core::ptr::null();
        }
    } else {
        // Resource record: type, class, ttl, rdlength, rdata.
        let rtype = match read_be_u16_at(buf, pos) {
            Some(v) => v,
            None => return -1,
        };
        let rclass = match read_be_u16_at(buf, pos + 2) {
            Some(v) => v,
            None => return -1,
        };
        let ttl = match read_be_u32_at(buf, pos + 4) {
            Some(v) => v,
            None => return -1,
        };
        let rdlen = match read_be_u16_at(buf, pos + 8) {
            Some(v) => v,
            None => return -1,
        };
        let rdata_off = pos + NS_RRFIXEDSZ;
        if rdata_off + (rdlen as usize) > msg_len {
            return -1;
        }
        let rdata = unsafe { msg_ptr.add(rdata_off) };
        // SAFETY: writable caller-supplied CNsRr.
        unsafe {
            (*rr)._type = rtype;
            (*rr).rr_class = rclass;
            (*rr).ttl = ttl;
            (*rr).rdlength = rdlen;
            (*rr).rdata = rdata;
        }
    }

    // Update the handle's "last accessed" cursor (mirrors glibc).
    // SAFETY: writable caller-supplied handle.
    unsafe {
        (*handle)._sect = section;
        (*handle)._rrnum = rrnum;
    }
    0
}

/// libresolv `ns_msg_getflag(handle, flag) -> int` — extract a
/// header flag from a parsed DNS message handle.
///
/// `flag` is the [`ns_flag`] enum value (0 = QR, 1 = opcode, 2 = AA,
/// 3 = TC, 4 = RD, 5 = RA, 6 = Z, 7 = AD, 8 = CD, 9 = RCODE).
///
/// # Safety
///
/// `handle` must be a [`CNsMsg`] previously initialized by
/// [`ns_initparse`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_msg_getflag(handle: *mut CNsMsg, flag: c_int) -> c_int {
    if handle.is_null() {
        return 0;
    }
    // SAFETY: caller-supplied initialized handle.
    let f = unsafe { (*handle)._flags };
    match flag {
        0 => ((f >> 15) & 0x01) as c_int, // QR
        1 => ((f >> 11) & 0x0F) as c_int, // opcode (4 bits)
        2 => ((f >> 10) & 0x01) as c_int, // AA
        3 => ((f >> 9) & 0x01) as c_int,  // TC
        4 => ((f >> 8) & 0x01) as c_int,  // RD
        5 => ((f >> 7) & 0x01) as c_int,  // RA
        6 => ((f >> 6) & 0x01) as c_int,  // Z
        7 => ((f >> 5) & 0x01) as c_int,  // AD
        8 => ((f >> 4) & 0x01) as c_int,  // CD
        9 => (f & 0x0F) as c_int,         // RCODE (4 bits)
        _ => 0,
    }
}

// ===========================================================================
// libresolv inet_neta — network number to text
// ===========================================================================

/// libresolv `inet_neta(src, dst, size) -> *mut c_char` — format an
/// `in_addr_t` as a CIDR-style network number string.
///
/// Algorithm: walk integer bytes from most-significant to
/// least-significant; emit a byte unless it is zero AND there are more
/// non-zero bytes remaining. This matches libresolv's integer
/// contract, where `0xc0a80100` formats as `"192.168.1"`. If the
/// address is 0 we emit `"0.0.0.0"`.
///
/// Examples:
///   - 0x7f000000 -> "127"
///   - 0xc0a80100 -> "192.168.1"
///   - 0xc0a80105 -> "192.168.1.5"
///
/// Sets `errno = EMSGSIZE` and returns NULL if `dst` is too small.
///
/// # Safety
///
/// `dst`, when non-NULL, must point to at least `size` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_neta(mut src: u32, dst: *mut c_char, size: usize) -> *mut c_char {
    if dst.is_null() {
        unsafe { set_abi_errno(libc::EMSGSIZE) };
        return core::ptr::null_mut();
    }
    let odst = dst;

    let mut tmp = [0u8; 16];
    let mut cursor = 0usize;
    if src == 0 {
        tmp[..7].copy_from_slice(b"0.0.0.0");
        cursor = 7;
    }

    while src != 0 {
        let b = (src >> 24) as u8;
        src <<= 8;
        if b != 0 || src == 0 {
            if cursor != 0 {
                tmp[cursor] = b'.';
                cursor += 1;
            }
            let mut digits = [0u8; 3];
            let mut n = b;
            let mut len = 0usize;
            if n == 0 {
                digits[0] = b'0';
                len = 1;
            } else {
                while n > 0 {
                    digits[len] = b'0' + (n % 10);
                    n /= 10;
                    len += 1;
                }
            }
            for i in 0..len {
                tmp[cursor + i] = digits[len - 1 - i];
            }
            cursor += len;
        }
    }

    let needed = cursor + 1;
    if size < needed {
        unsafe { set_abi_errno(libc::EMSGSIZE) };
        return core::ptr::null_mut();
    }
    tmp[cursor] = 0;
    // SAFETY: dst has at least needed bytes and tmp contains needed bytes.
    unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr() as *const c_char, dst, needed) };
    odst
}

// ===========================================================================
// libresolv ns_sprintrr / ns_sprintrrf — DNS RR text formatter
// ===========================================================================
//
// Emits one resource record in BIND zone-file syntax:
//
//     name TTL class type rdata
//
// Per-type rdata formatting covers the common types (A, AAAA, NS,
// CNAME, PTR, MX, TXT). Unknown types fall back to the RFC 3597
// generic representation: `\# <rdlen> <hex bytes>`.

fn write_class_into(class: u16, out: &mut String) {
    use std::fmt::Write;
    match class {
        1 => out.push_str("IN"),
        2 => out.push_str("CS"),
        3 => out.push_str("CH"),
        4 => out.push_str("HS"),
        n => {
            let _ = write!(out, "CLASS{n}");
        }
    }
}

fn write_type_into(ty: u16, out: &mut String) {
    use std::fmt::Write;
    match ty {
        1 => out.push('A'),
        2 => out.push_str("NS"),
        5 => out.push_str("CNAME"),
        12 => out.push_str("PTR"),
        15 => out.push_str("MX"),
        16 => out.push_str("TXT"),
        28 => out.push_str("AAAA"),
        n => {
            let _ = write!(out, "TYPE{n}");
        }
    }
}

fn format_a_rdata(rdata: &[u8], out: &mut String) -> Result<(), ()> {
    if rdata.len() != 4 {
        return Err(());
    }
    use std::fmt::Write;
    let _ = write!(out, "{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]);
    Ok(())
}

fn format_aaaa_rdata(rdata: &[u8], out: &mut String) -> Result<(), ()> {
    if rdata.len() != 16 {
        return Err(());
    }
    let bytes: [u8; 16] = rdata.try_into().map_err(|_| ())?;
    let v6 = std::net::Ipv6Addr::from(bytes);
    use std::fmt::Write;
    let _ = write!(out, "{v6}");
    Ok(())
}

unsafe fn format_name_rdata(
    msg: *const u8,
    msglen: usize,
    rdata: *const u8,
    out: &mut String,
) -> Result<(), ()> {
    if msg.is_null() || rdata.is_null() {
        return Err(());
    }
    let mut tmp = [0u8; NS_MAXDNAME];
    let eom = unsafe { msg.add(msglen) };
    let n = unsafe {
        crate::unistd_abi::dn_expand(
            msg,
            eom,
            rdata,
            tmp.as_mut_ptr() as *mut c_char,
            NS_MAXDNAME as c_int,
        )
    };
    if n < 0 {
        return Err(());
    }
    let len = tmp.iter().position(|&b| b == 0).unwrap_or(tmp.len());
    out.push_str(&String::from_utf8_lossy(&tmp[..len]));
    Ok(())
}

fn format_txt_rdata(rdata: &[u8], out: &mut String) -> Result<(), ()> {
    use std::fmt::Write;
    let mut i = 0usize;
    let mut first = true;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        if i + len > rdata.len() {
            return Err(());
        }
        if !first {
            out.push(' ');
        }
        first = false;
        out.push('"');
        for &b in &rdata[i..i + len] {
            if b == b'"' || b == b'\\' {
                out.push('\\');
                out.push(b as char);
            } else if (32..127).contains(&b) {
                out.push(b as char);
            } else {
                let _ = write!(out, "\\{b:03}");
            }
        }
        out.push('"');
        i += len;
    }
    Ok(())
}

fn format_generic_rdata(rdata: &[u8], out: &mut String) {
    use std::fmt::Write;
    let _ = write!(out, "\\# {}", rdata.len());
    if !rdata.is_empty() {
        out.push(' ');
        for &b in rdata {
            let _ = write!(out, "{b:02X}");
        }
    }
}

unsafe fn format_rdata(
    msg: *const u8,
    msglen: usize,
    ty: u16,
    rdata: *const u8,
    rdlen: usize,
    out: &mut String,
) -> Result<(), ()> {
    let slice = if rdata.is_null() {
        if rdlen != 0 {
            return Err(());
        }
        &[][..]
    } else {
        // SAFETY: caller-supplied rdata buffer of rdlen bytes.
        unsafe { core::slice::from_raw_parts(rdata, rdlen) }
    };
    match ty {
        1 => format_a_rdata(slice, out),
        28 => format_aaaa_rdata(slice, out),
        2 | 5 | 12 => unsafe { format_name_rdata(msg, msglen, rdata, out) },
        15 => {
            // MX: 2-byte preference + name
            if slice.len() < 3 {
                return Err(());
            }
            let pref = u16::from_be_bytes([slice[0], slice[1]]);
            use std::fmt::Write;
            let _ = write!(out, "{pref} ");
            unsafe { format_name_rdata(msg, msglen, rdata.add(2), out) }
        }
        16 => format_txt_rdata(slice, out),
        _ => {
            format_generic_rdata(slice, out);
            Ok(())
        }
    }
}

/// libresolv `ns_sprintrrf(msg, msglen, name, class, type, ttl,
/// rdata, rdlen, name_ctx, origin, buf, buflen) -> int` — format
/// one DNS resource record in BIND zone-file syntax.
///
/// `name_ctx` and `origin` are accepted for ABI compatibility but
/// not used (the BIND reference uses them for zone-relative name
/// shortening; we always emit fully-qualified names).
///
/// Returns the number of bytes written (excluding the terminating
/// NUL) on success, or -1 on overflow / malformed rdata.
///
/// # Safety
///
/// All pointer arguments must point to readable buffers of the
/// declared sizes. `buf`, when non-NULL, must point to at least
/// `buflen` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ns_sprintrrf(
    msg: *const u8,
    msglen: usize,
    name: *const c_char,
    class: u16,
    ty: u16,
    ttl: u32,
    rdata: *const u8,
    rdlen: usize,
    _name_ctx: *const c_char,
    _origin: *const c_char,
    buf: *mut c_char,
    buflen: usize,
) -> c_int {
    if buf.is_null() || name.is_null() || buflen == 0 {
        return -1;
    }
    let Some(name_bytes) = (unsafe { required_cstr_bytes(name) }) else {
        return -1;
    };
    let name_str = String::from_utf8_lossy(name_bytes);

    let mut out = String::new();
    out.push_str(&name_str);
    out.push(' ');

    let mut ttl_buf = [0u8; 32];
    let ttl_n = unsafe {
        ns_format_ttl(
            ttl.into(),
            ttl_buf.as_mut_ptr() as *mut c_char,
            ttl_buf.len(),
        )
    };
    if ttl_n < 0 {
        return -1;
    }
    out.push_str(&String::from_utf8_lossy(&ttl_buf[..ttl_n as usize]));
    out.push(' ');

    write_class_into(class, &mut out);
    out.push(' ');
    write_type_into(ty, &mut out);
    out.push(' ');

    if unsafe { format_rdata(msg, msglen, ty, rdata, rdlen, &mut out) }.is_err() {
        return -1;
    }

    let bytes = out.as_bytes();
    let needed = bytes.len() + 1;
    if needed > buflen {
        return -1;
    }
    // SAFETY: buf has buflen >= needed bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf, bytes.len());
        *buf.add(bytes.len()) = 0;
    }
    bytes.len() as c_int
}

/// libresolv `ns_sprintrr(handle, rr, name_ctx, origin, buf,
/// buflen) -> int` — extract the fields from a parsed
/// [`CNsMsg`] / [`CNsRr`] pair and forward to [`ns_sprintrrf`].
///
/// # Safety
///
/// `handle` and `rr` must be initialized (typically via
/// [`ns_initparse`] + [`ns_parserr`]).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_sprintrr(
    handle: *const CNsMsg,
    rr: *const CNsRr,
    name_ctx: *const c_char,
    origin: *const c_char,
    buf: *mut c_char,
    buflen: usize,
) -> c_int {
    if handle.is_null() || rr.is_null() {
        return -1;
    }
    // SAFETY: caller-supplied initialized handle/rr.
    let msg = unsafe { (*handle)._msg };
    let eom = unsafe { (*handle)._eom };
    if msg.is_null() || eom.is_null() || (eom as usize) < (msg as usize) {
        return -1;
    }
    let msglen = (eom as usize) - (msg as usize);
    let rr_name = unsafe { &(*rr).name };
    if !rr_name.contains(&0) {
        return -1;
    }
    let name = unsafe { (*rr).name.as_ptr() };
    let class = unsafe { (*rr).rr_class };
    let ty = unsafe { (*rr)._type };
    let ttl = unsafe { (*rr).ttl };
    let rdata = unsafe { (*rr).rdata };
    let rdlen = unsafe { (*rr).rdlength } as usize;
    unsafe {
        ns_sprintrrf(
            msg, msglen, name, class, ty, ttl, rdata, rdlen, name_ctx, origin, buf, buflen,
        )
    }
}

// ===========================================================================
// 37 libresolv last-mile helpers (bd-dcfj5)
// ===========================================================================
//
// libresolv exports a long tail of GLIBC_PRIVATE byte-order helpers, DNS
// debug-print formatters, HOSTALIASES lookup hooks, RFC 1876 LOC encoders,
// DNS symbol-table lookups, resolver-state lifecycle helpers, and an
// /etc/hosts iteration API. None of these are critical for normal name
// resolution (the public ns_*, dn_*, getaddrinfo paths cover that), so we
// ship safe defaults that match the "no extra resolver state, no debug
// print, no LOC support, no hosts iteration" contract.

// --- Byte-order primitives (network big-endian) ---

/// `__ns_get16(*src) -> c_uint` — GLIBC_PRIVATE alias for `ns_get16`.
///
/// # Safety
/// `src` must point to at least 2 readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ns_get16(src: *const u8) -> libc::c_uint {
    unsafe { ns_get16(src) }
}

/// `__ns_get32(*src) -> c_ulong` — GLIBC_PRIVATE alias for `ns_get32`.
///
/// # Safety
/// `src` must point to at least 4 readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ns_get32(src: *const u8) -> libc::c_ulong {
    unsafe { ns_get32(src) }
}

/// `_getshort(*src) -> u16` — read 16 bits in network byte order.
///
/// # Safety
/// `src` must point to at least 2 readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _getshort(src: *const u8) -> u16 {
    if src.is_null() || !tracked_region_fits(src.cast(), 2) {
        return 0;
    }
    let s = unsafe { core::slice::from_raw_parts(src, 2) };
    u16::from_be_bytes([s[0], s[1]])
}

/// `_getlong(*src) -> u32` — read 32 bits in network byte order.
///
/// # Safety
/// `src` must point to at least 4 readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _getlong(src: *const u8) -> u32 {
    if src.is_null() || !tracked_region_fits(src.cast(), 4) {
        return 0;
    }
    let s = unsafe { core::slice::from_raw_parts(src, 4) };
    u32::from_be_bytes([s[0], s[1], s[2], s[3]])
}

/// `__putshort(value, *dst)` — write 16 bits in network byte order.
///
/// # Safety
/// `dst` must point to at least 2 writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __putshort(value: u16, dst: *mut u8) {
    if dst.is_null() || !tracked_region_fits(dst.cast(), 2) {
        return;
    }
    let bytes = value.to_be_bytes();
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, 2) };
}

/// `__putlong(value, *dst)` — write 32 bits in network byte order.
///
/// # Safety
/// `dst` must point to at least 4 writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __putlong(value: u32, dst: *mut u8) {
    if dst.is_null() || !tracked_region_fits(dst.cast(), 4) {
        return;
    }
    let bytes = value.to_be_bytes();
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, 4) };
}

// --- DNS debug printers ---
// Real callers use these for `res_search` debug logging. We expose them as
// stubs that return 0 / write nothing — programs that request DNS debug
// output get an empty stream rather than a crash.

/// `__fp_query(*msg, *file) -> ()` — debug-print a DNS query message.
/// Stub no-op (we don't render packets to FILE* streams).
///
/// # Safety
/// Both pointers may be NULL; we don't dereference them.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fp_query(_msg: *const u8, _file: *mut c_void) {}

/// `__fp_nquery(*msg, len, *file) -> ()` — sized variant of `__fp_query`.
///
/// # Safety
/// Both pointers may be NULL; we don't dereference them.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fp_nquery(_msg: *const u8, _len: c_int, _file: *mut c_void) {}

/// `__fp_resstat(*statp, *file) -> ()` — print resolver state. Stub
/// no-op.
///
/// # Safety
/// Both pointers may be NULL; we don't dereference them.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fp_resstat(_statp: *const c_void, _file: *mut c_void) {}

// All `__p_*` helpers below take values and write a textual rep to a
// FILE* or return a `*const c_char`. The look-up variants below replicate
// glibc's static-table → fallback-decimal-buffer behavior; the writing
// variants stay no-ops since we don't render to FILE* streams.

thread_local! {
    /// Per-thread fallback buffer for `__p_class` / `__p_type` decimal
    /// fallbacks (matches glibc which uses a static buffer).
    static P_FALLBACK_BUF: core::cell::UnsafeCell<[u8; 16]> =
        const { core::cell::UnsafeCell::new([0u8; 16]) };
}

unsafe fn write_decimal_fallback(value: c_int) -> *const c_char {
    P_FALLBACK_BUF.with(|cell| {
        let buf_ptr = cell.get();
        // SAFETY: thread-local; no aliasing across threads.
        let buf = unsafe { &mut *buf_ptr };
        let s = format!("{value}");
        let bytes = s.as_bytes();
        let n = bytes.len().min(buf.len() - 1);
        buf[..n].copy_from_slice(&bytes[..n]);
        buf[n] = 0;
        buf.as_ptr() as *const c_char
    })
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __p_class(class: c_int) -> *const c_char {
    // RFC 1035 / glibc class names. Uses CSNET (class 2) is unknown.
    match class {
        1 => c"IN".as_ptr(),
        3 => c"CHAOS".as_ptr(),
        4 => c"HS".as_ptr(),
        255 => c"ANY".as_ptr(),
        _ => unsafe { write_decimal_fallback(class) },
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __p_type(ty: c_int) -> *const c_char {
    // RFC 1035 + RFC 3596 (AAAA) + RFC 2782 (SRV) + RFC 6891 (OPT) + …
    // Mapping mirrors glibc's __p_type_syms.
    match ty {
        1 => c"A".as_ptr(),
        2 => c"NS".as_ptr(),
        3 => c"MD".as_ptr(),
        4 => c"MF".as_ptr(),
        5 => c"CNAME".as_ptr(),
        6 => c"SOA".as_ptr(),
        7 => c"MB".as_ptr(),
        8 => c"MG".as_ptr(),
        9 => c"MR".as_ptr(),
        10 => c"NULL".as_ptr(),
        11 => c"WKS".as_ptr(),
        12 => c"PTR".as_ptr(),
        13 => c"HINFO".as_ptr(),
        14 => c"MINFO".as_ptr(),
        15 => c"MX".as_ptr(),
        16 => c"TXT".as_ptr(),
        17 => c"RP".as_ptr(),
        18 => c"AFSDB".as_ptr(),
        19 => c"X25".as_ptr(),
        20 => c"ISDN".as_ptr(),
        21 => c"RT".as_ptr(),
        22 => c"NSAP".as_ptr(),
        23 => c"NSAP_PTR".as_ptr(),
        24 => c"SIG".as_ptr(),
        25 => c"KEY".as_ptr(),
        28 => c"AAAA".as_ptr(),
        29 => c"LOC".as_ptr(),
        33 => c"SRV".as_ptr(),
        35 => c"NAPTR".as_ptr(),
        36 => c"KX".as_ptr(),
        37 => c"CERT".as_ptr(),
        39 => c"DNAME".as_ptr(),
        41 => c"OPT".as_ptr(),
        43 => c"DS".as_ptr(),
        46 => c"RRSIG".as_ptr(),
        47 => c"NSEC".as_ptr(),
        48 => c"DNSKEY".as_ptr(),
        50 => c"NSEC3".as_ptr(),
        51 => c"NSEC3PARAM".as_ptr(),
        52 => c"TLSA".as_ptr(),
        65 => c"HTTPS".as_ptr(),
        249 => c"TKEY".as_ptr(),
        250 => c"TSIG".as_ptr(),
        251 => c"IXFR".as_ptr(),
        252 => c"AXFR".as_ptr(),
        253 => c"MAILB".as_ptr(),
        254 => c"MAILA".as_ptr(),
        255 => c"ANY".as_ptr(),
        257 => c"CAA".as_ptr(),
        _ => unsafe { write_decimal_fallback(ty) },
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __p_option(option: c_int) -> *const c_char {
    // RES_* option flags (from <resolv.h>). glibc returns the symbol
    // name for known single-bit flags or "?0xVAL?" for unknown.
    match option {
        0x0001 => c"init".as_ptr(),
        0x0002 => c"debug".as_ptr(),
        0x0008 => c"use-vc".as_ptr(),
        0x0020 => c"igntc".as_ptr(),
        0x0040 => c"recurs".as_ptr(),
        0x0080 => c"defnam".as_ptr(),
        0x0100 => c"styopn".as_ptr(),
        0x0200 => c"dnsrch".as_ptr(),
        0x1000 => c"noaliases".as_ptr(),
        0x4000 => c"rotate".as_ptr(),
        _ => {
            thread_local! {
                static P_OPTION_BUF: core::cell::UnsafeCell<[u8; 24]> =
                    const { core::cell::UnsafeCell::new([0u8; 24]) };
            }
            P_OPTION_BUF.with(|cell| {
                let buf_ptr = cell.get();
                // SAFETY: thread-local; no aliasing across threads.
                let buf = unsafe { &mut *buf_ptr };
                let s = format!("?0x{:x}?", option as u32);
                let bytes = s.as_bytes();
                let n = bytes.len().min(buf.len() - 1);
                buf[..n].copy_from_slice(&bytes[..n]);
                buf[n] = 0;
                buf.as_ptr() as *const c_char
            })
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __p_rcode(rcode: c_int) -> *const c_char {
    // RFC 1035 + RFC 2136 + RFC 2845 + RFC 6195 (DNS RCODE registry)
    match rcode {
        0 => c"NOERROR".as_ptr(),
        1 => c"FORMERR".as_ptr(),
        2 => c"SERVFAIL".as_ptr(),
        3 => c"NXDOMAIN".as_ptr(),
        4 => c"NOTIMP".as_ptr(),
        5 => c"REFUSED".as_ptr(),
        6 => c"YXDOMAIN".as_ptr(),
        7 => c"YXRRSET".as_ptr(),
        8 => c"NXRRSET".as_ptr(),
        9 => c"NOTAUTH".as_ptr(),
        10 => c"NOTZONE".as_ptr(),
        16 => c"BADSIG".as_ptr(),
        17 => c"BADKEY".as_ptr(),
        18 => c"BADTIME".as_ptr(),
        _ => unsafe { write_decimal_fallback(rcode) },
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __p_secstodate(secs: u32) -> *const c_char {
    // glibc renders the SOA SERIAL / RRSIG signature time as
    // YYYYMMDDHHMMSS in UTC. fl uses the same closed-form date
    // conversion that powers gmtime_r (no syscalls).
    use frankenlibc_core::time as time_core;
    thread_local! {
        static SECSTODATE_BUF: core::cell::UnsafeCell<[u8; 24]> =
            const { core::cell::UnsafeCell::new([0u8; 24]) };
    }
    SECSTODATE_BUF.with(|cell| {
        let buf_ptr = cell.get();
        // SAFETY: thread-local; no aliasing across threads.
        let buf = unsafe { &mut *buf_ptr };
        let bd = time_core::epoch_to_broken_down(secs as i64);
        let year = (bd.tm_year as i64 + 1900).clamp(0, 9999) as u32;
        let s = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            year,
            (bd.tm_mon + 1) as u32,
            bd.tm_mday as u32,
            bd.tm_hour as u32,
            bd.tm_min as u32,
            bd.tm_sec as u32,
        );
        let bytes = s.as_bytes();
        let n = bytes.len().min(buf.len() - 1);
        buf[..n].copy_from_slice(&bytes[..n]);
        buf[n] = 0;
        buf.as_ptr() as *const c_char
    })
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __p_time(value: u32) -> *const c_char {
    // __p_time renders a TTL using the same W/D/H/M/S decomposition as
    // ns_format_ttl. We share the same thread-local buffer to avoid
    // duplicating the formatter; the output format ("1D", "2w6h56m7s")
    // is identical.
    thread_local! {
        static P_TIME_BUF: core::cell::UnsafeCell<[u8; 32]> =
            const { core::cell::UnsafeCell::new([0u8; 32]) };
    }
    P_TIME_BUF.with(|cell| {
        let buf_ptr = cell.get();
        // SAFETY: thread-local; no aliasing across threads.
        let buf = unsafe { &mut *buf_ptr };
        let n = unsafe {
            ns_format_ttl(
                value as libc::c_ulong,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
            )
        };
        if n < 0 {
            // Fallback shouldn't happen for u32 inputs in a 32-byte buffer.
            buf[0] = b'0';
            buf[1] = b'S';
            buf[2] = 0;
        }
        buf.as_ptr() as *const c_char
    })
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __p_query(_msg: *const u8) {}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __p_cdname(
    _cp: *const u8,
    _msg: *const u8,
    _file: *mut c_void,
) -> *const u8 {
    core::ptr::null()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __p_cdnname(
    _cp: *const u8,
    _msg: *const u8,
    _len: c_int,
    _file: *mut c_void,
) -> *const u8 {
    core::ptr::null()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __p_fqname(
    _cp: *const u8,
    _msg: *const u8,
    _file: *mut c_void,
) -> *const u8 {
    core::ptr::null()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __p_fqnname(
    _cp: *const u8,
    _msg: *const u8,
    _msglen: c_int,
    _name: *mut c_char,
    _namelen: c_int,
) -> *const u8 {
    core::ptr::null()
}

// --- HOSTALIASES ---

const HOSTALIAS_BUF_LEN: usize = 1025;

thread_local! {
    static HOSTALIAS_BUF: RefCell<[u8; HOSTALIAS_BUF_LEN]> =
        const { RefCell::new([0u8; HOSTALIAS_BUF_LEN]) };
}

fn hostalias_lookup(name: &[u8], hosts_file: &str) -> Option<Vec<u8>> {
    let contents = std::fs::read_to_string(hosts_file).ok()?;
    for line in contents.lines() {
        // Skip comments and blank lines.
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Split on first whitespace run: alias, then dns name.
        let mut it = line.split_whitespace();
        let alias = it.next()?;
        let dns = it.next()?;
        if alias.as_bytes().eq_ignore_ascii_case(name) {
            return Some(dns.as_bytes().to_vec());
        }
    }
    None
}

unsafe fn hostalias_name_bytes<'a>(name: *const c_char) -> Option<&'a [u8]> {
    let Ok(Some(name_cstr)) = (unsafe { opt_cstr(name) }) else {
        return None;
    };
    let name_bytes = name_cstr.to_bytes();
    if name_bytes.is_empty() {
        None
    } else {
        Some(name_bytes)
    }
}

/// `__hostalias(*name) -> *const c_char` — lookup HOSTALIASES alias.
/// Reads `$HOSTALIASES` (a path to a file with `alias dnsname` lines),
/// case-insensitively matches `name` against the first column, and
/// returns a pointer to a thread-local static buffer holding the DNS
/// name. Returns NULL if `$HOSTALIASES` is unset, the file is missing,
/// or no alias matches.
///
/// # Safety
/// `name` may be NULL; we return NULL in that case. Otherwise it must
/// point to a NUL-terminated C string. The returned pointer is valid
/// until the next call from the same thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __hostalias(name: *const c_char) -> *const c_char {
    let Some(name_bytes) = (unsafe { hostalias_name_bytes(name) }) else {
        return core::ptr::null();
    };
    let Ok(file) = std::env::var("HOSTALIASES") else {
        return core::ptr::null();
    };
    let Some(dns) = hostalias_lookup(name_bytes, &file) else {
        return core::ptr::null();
    };
    // Cap to buffer size minus the NUL terminator.
    let copy_len = dns.len().min(HOSTALIAS_BUF_LEN - 1);
    HOSTALIAS_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf[..copy_len].copy_from_slice(&dns[..copy_len]);
        buf[copy_len] = 0;
        // Return pointer to the thread-local buffer. Casting through
        // a raw pointer here is the standard pattern for handing back
        // a static-lifetime view of TLS storage.
        buf.as_ptr() as *const c_char
    })
}

/// `__res_hostalias(*statp, *name, *buf, buflen) -> *const c_char` —
/// reentrant variant of `__hostalias`. Writes the resolved DNS name
/// into the caller-supplied `buf` (NUL-terminated, capped at `buflen`)
/// and returns `buf` on success. Returns NULL on miss, missing
/// `$HOSTALIASES`, or invalid arguments. The `statp` resolver state
/// is unused — the lookup is identical to `__hostalias`'s.
///
/// # Safety
/// `name` must be NULL or NUL-terminated. `buf`, when non-NULL, must
/// point to at least `buflen` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_hostalias(
    _statp: *mut c_void,
    name: *const c_char,
    buf: *mut c_char,
    buflen: usize,
) -> *const c_char {
    if buf.is_null() || buflen == 0 {
        return core::ptr::null();
    }
    let Some(name_bytes) = (unsafe { hostalias_name_bytes(name) }) else {
        return core::ptr::null();
    };
    let Ok(file) = std::env::var("HOSTALIASES") else {
        return core::ptr::null();
    };
    let Some(dns) = hostalias_lookup(name_bytes, &file) else {
        return core::ptr::null();
    };
    let effective_buflen =
        known_remaining(buf as usize).map_or(buflen, |remaining| remaining.min(buflen));
    if effective_buflen == 0 {
        return core::ptr::null();
    }
    let copy_len = dns.len().min(effective_buflen - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(dns.as_ptr(), buf as *mut u8, copy_len);
        *(buf.add(copy_len)) = 0;
    }
    buf
}

// --- RFC 1876 LOC records ---

const LOC_NTOA_BUF_LEN: usize = 96;

thread_local! {
    static LOC_NTOA_BUF: RefCell<[u8; LOC_NTOA_BUF_LEN]> =
        const { RefCell::new([0u8; LOC_NTOA_BUF_LEN]) };
}

const POWERS_OF_TEN: [u64; 10] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
];

/// Format a precision byte (mantissa-exponent encoded centimeters) as
/// "<meters>.<centi-meters-2dp>" — matches glibc's `precsize_ntoa`.
fn loc_precsize_format(prec: u8) -> String {
    let mantissa = ((prec >> 4) & 0x0f) as usize % 10;
    let exponent = (prec & 0x0f) as usize % 10;
    let val = (mantissa as u64) * POWERS_OF_TEN[exponent];
    format!("{}.{:02}", val / 100, val % 100)
}

/// Parse a "<meters>[.<frac>]" string into a precision byte. Returns
/// the byte plus the number of input bytes consumed (whitespace not
/// included). On parse failure returns None.
fn loc_precsize_parse(s: &[u8]) -> Option<(u8, usize)> {
    // Match optional digits, optional '.', optional digits, optional 'm'.
    let mut i = 0;
    let start = i;
    while i < s.len() && s[i].is_ascii_digit() {
        i += 1;
    }
    let int_end = i;
    let mut frac_end = i;
    if i < s.len() && s[i] == b'.' {
        i += 1;
        while i < s.len() && s[i].is_ascii_digit() {
            i += 1;
        }
        frac_end = i;
    }
    if int_end == start && frac_end == start {
        return None;
    }
    if i < s.len() && s[i] == b'm' {
        i += 1;
    }
    let int_str = std::str::from_utf8(&s[start..int_end]).ok()?;
    let int_meters: u64 = if int_str.is_empty() {
        0
    } else {
        int_str.parse().ok()?
    };
    let frac_part: u64 = if frac_end > int_end + 1 {
        // We have a '.' + digits.
        let frac_str = std::str::from_utf8(&s[int_end + 1..frac_end]).ok()?;
        // Pad/truncate to 2 digits so we get centimeters.
        let mut buf = String::from(frac_str);
        if buf.len() < 2 {
            while buf.len() < 2 {
                buf.push('0');
            }
        } else {
            buf.truncate(2);
        }
        buf.parse().ok()?
    } else {
        0
    };
    let cm = int_meters.checked_mul(100)?.checked_add(frac_part)?;
    // Choose the smallest exponent that keeps mantissa <= 9.
    let mut mantissa = cm;
    let mut exponent = 0u8;
    while mantissa > 9 && exponent < 9 {
        mantissa /= 10;
        exponent += 1;
    }
    if mantissa > 9 {
        // Out of range.
        return None;
    }
    Some((((mantissa as u8) << 4) | exponent, i))
}

/// `__loc_aton(*ascii, *binary) -> int` — parse LOC ASCII rep per
/// RFC 1876 into 16-byte binary. Returns 1 on success, 0 on failure.
///
/// Format: `<lat-d> <lat-m> <lat-s>[.<frac>] <N|S> <lon-d> <lon-m>
/// <lon-s>[.<frac>] <E|W> <alt>[m] [<size>[m] [<hp>[m] [<vp>[m]]]]`
/// where minutes/seconds default to 0 if omitted (we still require the
/// hemisphere letter to disambiguate end-of-coordinate).
///
/// # Safety
/// Pointers may be NULL; we return 0 in that case.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __loc_aton(ascii: *const c_char, binary: *mut u8) -> c_int {
    if ascii.is_null() || binary.is_null() {
        return 0;
    }
    let s = unsafe { CStr::from_ptr(ascii) }.to_bytes();
    let Some(out) = loc_aton_inner(s) else {
        return 0;
    };
    let dst = unsafe { std::slice::from_raw_parts_mut(binary, 16) };
    dst.copy_from_slice(&out);
    // Match glibc: return the size of the LOC RR (16 bytes) on success.
    16
}

fn loc_aton_inner(s: &[u8]) -> Option<[u8; 16]> {
    let mut tokens = LocTokens::new(s);

    // Latitude: deg [min [sec[.frac]]] (N|S)
    let lat_deg: u32 = tokens.next_u32()?;
    if lat_deg > 90 {
        return None;
    }
    let mut lat_min: u32 = 0;
    let mut lat_sec_int: u32 = 0;
    let mut lat_sec_frac: u32 = 0;
    let mut tok = tokens.next_token()?;
    if !is_hemisphere(tok) {
        lat_min = parse_u32(tok)?;
        if lat_min >= 60 {
            return None;
        }
        tok = tokens.next_token()?;
        if !is_hemisphere(tok) {
            let (sec_int, sec_frac) = parse_seconds(tok)?;
            lat_sec_int = sec_int;
            lat_sec_frac = sec_frac;
            if lat_sec_int >= 60 {
                return None;
            }
            tok = tokens.next_token()?;
        }
    }
    let north_south = match tok {
        b"N" | b"n" => 1i64,
        b"S" | b"s" => -1i64,
        _ => return None,
    };

    // Longitude: deg [min [sec[.frac]]] (E|W)
    let lon_deg: u32 = tokens.next_u32()?;
    if lon_deg > 180 {
        return None;
    }
    let mut lon_min: u32 = 0;
    let mut lon_sec_int: u32 = 0;
    let mut lon_sec_frac: u32 = 0;
    let mut tok = tokens.next_token()?;
    if !is_hemisphere(tok) {
        lon_min = parse_u32(tok)?;
        if lon_min >= 60 {
            return None;
        }
        tok = tokens.next_token()?;
        if !is_hemisphere(tok) {
            let (sec_int, sec_frac) = parse_seconds(tok)?;
            lon_sec_int = sec_int;
            lon_sec_frac = sec_frac;
            if lon_sec_int >= 60 {
                return None;
            }
            tok = tokens.next_token()?;
        }
    }
    let east_west = match tok {
        b"E" | b"e" => 1i64,
        b"W" | b"w" => -1i64,
        _ => return None,
    };

    // Altitude (with optional 'm' suffix, optional fractional, optional sign)
    let alt_tok = tokens.next_token()?;
    let alt_meters_centi = parse_signed_meters(alt_tok)?;

    // Defaults: size=1m, horiz_pre=10km, vert_pre=10m
    let mut size_byte: u8 = 0x12;
    let mut hp_byte: u8 = 0x16;
    let mut vp_byte: u8 = 0x13;
    if let Some(t) = tokens.peek_token() {
        size_byte = loc_precsize_parse(t)?.0;
        tokens.consume_token();
    }
    if let Some(t) = tokens.peek_token() {
        hp_byte = loc_precsize_parse(t)?.0;
        tokens.consume_token();
    }
    if let Some(t) = tokens.peek_token() {
        vp_byte = loc_precsize_parse(t)?.0;
        tokens.consume_token();
    }
    if tokens.peek_token().is_some() {
        return None; // trailing garbage
    }

    // Build latitude/longitude in milli-arcseconds (signed).
    let lat_ms: i64 = north_south
        * (lat_deg as i64 * 3_600_000
            + lat_min as i64 * 60_000
            + lat_sec_int as i64 * 1_000
            + lat_sec_frac as i64);
    let lon_ms: i64 = east_west
        * (lon_deg as i64 * 3_600_000
            + lon_min as i64 * 60_000
            + lon_sec_int as i64 * 1_000
            + lon_sec_frac as i64);

    // Latitude/longitude reference is 2^31 (equator, prime meridian).
    let ref_pos: i64 = 1i64 << 31;
    let lat_word = (ref_pos + lat_ms) as u32;
    let lon_word = (ref_pos + lon_ms) as u32;

    // Altitude reference is -100,000m, stored in cm.
    let alt_word = (alt_meters_centi + 10_000_000_i64) as u32;

    let mut out = [0u8; 16];
    out[0] = 0; // version
    out[1] = size_byte;
    out[2] = hp_byte;
    out[3] = vp_byte;
    out[4..8].copy_from_slice(&lat_word.to_be_bytes());
    out[8..12].copy_from_slice(&lon_word.to_be_bytes());
    out[12..16].copy_from_slice(&alt_word.to_be_bytes());
    Some(out)
}

fn is_hemisphere(tok: &[u8]) -> bool {
    matches!(tok, b"N" | b"n" | b"S" | b"s" | b"E" | b"e" | b"W" | b"w")
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    std::str::from_utf8(s).ok()?.parse().ok()
}

fn parse_seconds(s: &[u8]) -> Option<(u32, u32)> {
    // Accept "ss" or "ss.fff" (frac ms, up to 3 digits).
    let dot = s.iter().position(|&b| b == b'.');
    match dot {
        None => Some((parse_u32(s)?, 0)),
        Some(idx) => {
            let int_str = std::str::from_utf8(&s[..idx]).ok()?;
            let int_val: u32 = if int_str.is_empty() {
                0
            } else {
                int_str.parse().ok()?
            };
            let frac_str = std::str::from_utf8(&s[idx + 1..]).ok()?;
            // Pad/truncate to 3 digits to express milliseconds.
            let mut buf = String::from(frac_str);
            if buf.len() < 3 {
                while buf.len() < 3 {
                    buf.push('0');
                }
            } else {
                buf.truncate(3);
            }
            let frac_val: u32 = if buf.is_empty() { 0 } else { buf.parse().ok()? };
            Some((int_val, frac_val))
        }
    }
}

fn parse_signed_meters(s: &[u8]) -> Option<i64> {
    let mut bytes = s;
    let neg = !bytes.is_empty() && bytes[0] == b'-';
    if neg || (!bytes.is_empty() && bytes[0] == b'+') {
        bytes = &bytes[1..];
    }
    // Strip optional trailing 'm'.
    if !bytes.is_empty() && *bytes.last().unwrap() == b'm' {
        bytes = &bytes[..bytes.len() - 1];
    }
    let dot = bytes.iter().position(|&b| b == b'.');
    let (int_part, frac_part_cm): (i64, i64) = match dot {
        None => {
            let v: i64 = parse_u32(bytes)? as i64;
            (v, 0)
        }
        Some(idx) => {
            let int_str = std::str::from_utf8(&bytes[..idx]).ok()?;
            let int_val: i64 = if int_str.is_empty() {
                0
            } else {
                int_str.parse().ok()?
            };
            let frac_str = std::str::from_utf8(&bytes[idx + 1..]).ok()?;
            let mut buf = String::from(frac_str);
            if buf.len() < 2 {
                while buf.len() < 2 {
                    buf.push('0');
                }
            } else {
                buf.truncate(2);
            }
            let frac_val: i64 = buf.parse().ok()?;
            (int_val, frac_val)
        }
    };
    let cm = int_part.checked_mul(100)?.checked_add(frac_part_cm)?;
    Some(if neg { -cm } else { cm })
}

struct LocTokens<'a> {
    src: &'a [u8],
    pos: usize,
}
impl<'a> LocTokens<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }
    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }
    fn peek_token(&mut self) -> Option<&'a [u8]> {
        self.skip_ws();
        let start = self.pos;
        let mut end = start;
        while end < self.src.len() && !self.src[end].is_ascii_whitespace() {
            end += 1;
        }
        if start == end {
            None
        } else {
            Some(&self.src[start..end])
        }
    }
    fn consume_token(&mut self) {
        self.skip_ws();
        while self.pos < self.src.len() && !self.src[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }
    fn next_token(&mut self) -> Option<&'a [u8]> {
        let t = self.peek_token()?;
        self.consume_token();
        Some(t)
    }
    fn next_u32(&mut self) -> Option<u32> {
        let t = self.next_token()?;
        parse_u32(t)
    }
}

/// `__loc_ntoa(*binary, *ascii) -> *const c_char` — render LOC binary
/// as ASCII per RFC 1876. Writes into `ascii` if non-NULL, else into
/// a thread-local static buffer. Returns the buffer pointer or an
/// error string for unknown versions.
///
/// # Safety
/// `binary` must point to at least 16 readable bytes when non-NULL.
/// `ascii`, if non-NULL, must have room for ~90 bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __loc_ntoa(binary: *const u8, ascii: *mut c_char) -> *const c_char {
    if binary.is_null() {
        return core::ptr::null();
    }
    let bytes = unsafe { std::slice::from_raw_parts(binary, 16) };
    let formatted = loc_ntoa_format(bytes);
    let formatted_bytes = formatted.as_bytes();

    if ascii.is_null() {
        // Write into thread-local static buffer.
        return LOC_NTOA_BUF.with(|cell| {
            let mut buf = cell.borrow_mut();
            let n = formatted_bytes.len().min(LOC_NTOA_BUF_LEN - 1);
            buf[..n].copy_from_slice(&formatted_bytes[..n]);
            buf[n] = 0;
            buf.as_ptr() as *const c_char
        });
    }
    // Write into caller-provided buffer (assumed >= 90 bytes).
    unsafe {
        let dst = ascii as *mut u8;
        std::ptr::copy_nonoverlapping(formatted_bytes.as_ptr(), dst, formatted_bytes.len());
        *dst.add(formatted_bytes.len()) = 0;
    }
    ascii
}

fn loc_ntoa_format(bytes: &[u8]) -> String {
    let version = bytes[0];
    if version != 0 {
        return "; error: unknown LOC RR version".to_string();
    }
    let size_byte = bytes[1];
    let hp_byte = bytes[2];
    let vp_byte = bytes[3];
    let lat_word = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let lon_word = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let alt_word = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

    let ref_pos: i64 = 1i64 << 31;
    let mut lat_val: i64 = lat_word as i64 - ref_pos;
    let north_south = if lat_val < 0 {
        lat_val = -lat_val;
        'S'
    } else {
        'N'
    };
    let lat_secfrac = (lat_val % 1000) as i32;
    let lat_v = lat_val / 1000;
    let lat_sec = (lat_v % 60) as i32;
    let lat_v = lat_v / 60;
    let lat_min = (lat_v % 60) as i32;
    let lat_deg = (lat_v / 60) as i32;

    let mut lon_val: i64 = lon_word as i64 - ref_pos;
    let east_west = if lon_val < 0 {
        lon_val = -lon_val;
        'W'
    } else {
        'E'
    };
    let lon_secfrac = (lon_val % 1000) as i32;
    let lon_v = lon_val / 1000;
    let lon_sec = (lon_v % 60) as i32;
    let lon_v = lon_v / 60;
    let lon_min = (lon_v % 60) as i32;
    let lon_deg = (lon_v / 60) as i32;

    let reference_alt: i64 = 100_000 * 100;
    let alt_signed = alt_word as i64 - reference_alt;
    let (alt_meters, alt_centi) = if alt_signed < 0 {
        // glibc: altmeters = (altval / 100) * altsign; altfrac = altval % 100
        // where altval = referencealt - templ (always positive).
        let altval = -alt_signed;
        (-(altval / 100), altval % 100)
    } else {
        let altval = alt_signed;
        (altval / 100, altval % 100)
    };

    let size_str = loc_precsize_format(size_byte);
    let hp_str = loc_precsize_format(hp_byte);
    let vp_str = loc_precsize_format(vp_byte);

    format!(
        "{} {:02} {:02}.{:03} {} {} {:02} {:02}.{:03} {} {}.{:02}m {}m {}m {}m",
        lat_deg,
        lat_min,
        lat_sec,
        lat_secfrac,
        north_south,
        lon_deg,
        lon_min,
        lon_sec,
        lon_secfrac,
        east_west,
        alt_meters,
        alt_centi,
        size_str,
        hp_str,
        vp_str,
    )
}

// --- DNS symbol tables ---

/// glibc's `struct res_sym` from `<arpa/nameser.h>`.
#[repr(C)]
struct ResSym {
    number: c_int,
    name: *const c_char,
    humanname: *const c_char,
}

const SYM_UNKNOWN_BUF_LEN: usize = 24;

thread_local! {
    static SYM_NTOP_BUF: RefCell<[u8; SYM_UNKNOWN_BUF_LEN]> =
        const { RefCell::new([0u8; SYM_UNKNOWN_BUF_LEN]) };
    static SYM_NTOS_BUF: RefCell<[u8; SYM_UNKNOWN_BUF_LEN]> =
        const { RefCell::new([0u8; SYM_UNKNOWN_BUF_LEN]) };
}

fn write_decimal_to_tls(
    cell: &'static std::thread::LocalKey<RefCell<[u8; SYM_UNKNOWN_BUF_LEN]>>,
    value: c_int,
) -> *const c_char {
    cell.with(|c| {
        let mut buf = c.borrow_mut();
        let s = format!("{value}");
        let bytes = s.as_bytes();
        let n = bytes.len().min(SYM_UNKNOWN_BUF_LEN - 1);
        buf[..n].copy_from_slice(&bytes[..n]);
        buf[n] = 0;
        buf.as_ptr() as *const c_char
    })
}

/// `__sym_ntop(*tab, value, *success) -> *const c_char` — find the
/// `humanname` entry for `value` in a NULL-terminated `struct res_sym`
/// table. On success sets `*success = 1` and returns the humanname.
/// On failure sets `*success = 0` and returns a thread-local string
/// containing the decimal representation of `value`.
///
/// # Safety
/// `tab` must be NULL or point to a NULL-terminated `struct res_sym`
/// array. `success` may be NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sym_ntop(
    tab: *const c_void,
    value: c_int,
    success: *mut c_int,
) -> *const c_char {
    if !tab.is_null() {
        let mut p = tab as *const ResSym;
        loop {
            // SAFETY: caller asserts `tab` is a NULL-terminated table.
            let entry = unsafe { &*p };
            if entry.name.is_null() {
                break;
            }
            if entry.number == value {
                if !success.is_null() {
                    unsafe { *success = 1 };
                }
                return entry.humanname;
            }
            p = unsafe { p.add(1) };
        }
    }
    if !success.is_null() {
        unsafe { *success = 0 };
    }
    write_decimal_to_tls(&SYM_NTOP_BUF, value)
}

/// `__sym_ntos(*tab, value, *success) -> *const c_char` — like
/// `__sym_ntop` but returns the symbol's short `name` rather than the
/// human-readable description.
///
/// # Safety
/// `tab` must be NULL or point to a NULL-terminated `struct res_sym`
/// array. `success` may be NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sym_ntos(
    tab: *const c_void,
    value: c_int,
    success: *mut c_int,
) -> *const c_char {
    if !tab.is_null() {
        let mut p = tab as *const ResSym;
        loop {
            let entry = unsafe { &*p };
            if entry.name.is_null() {
                break;
            }
            if entry.number == value {
                if !success.is_null() {
                    unsafe { *success = 1 };
                }
                return entry.name;
            }
            p = unsafe { p.add(1) };
        }
    }
    if !success.is_null() {
        unsafe { *success = 0 };
    }
    write_decimal_to_tls(&SYM_NTOS_BUF, value)
}

/// `__sym_ston(*tab, *str, *success) -> int` — case-insensitive text
/// lookup against the `name` column of a NULL-terminated
/// `struct res_sym` array. On match sets `*success = 1` and returns
/// the matching `number`. On miss sets `*success = 0` and returns
/// the `number` field of the sentinel (unknown) entry.
///
/// # Safety
/// `tab` must be NULL or point to a NULL-terminated `struct res_sym`
/// array. `str` and `success` may be NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sym_ston(
    tab: *const c_void,
    str: *const c_char,
    success: *mut c_int,
) -> c_int {
    if !tab.is_null() && !str.is_null() {
        let needle = unsafe { CStr::from_ptr(str) }.to_bytes();
        let mut p = tab as *const ResSym;
        loop {
            let entry = unsafe { &*p };
            if entry.name.is_null() {
                // Sentinel entry: report failure but return its number,
                // matching libresolv's "unknown" semantics.
                if !success.is_null() {
                    unsafe { *success = 0 };
                }
                return entry.number;
            }
            let name_bytes = unsafe { CStr::from_ptr(entry.name) }.to_bytes();
            if name_bytes.eq_ignore_ascii_case(needle) {
                if !success.is_null() {
                    unsafe { *success = 1 };
                }
                return entry.number;
            }
            p = unsafe { p.add(1) };
        }
    }
    if !success.is_null() {
        unsafe { *success = 0 };
    }
    0
}

// --- Resolver lifecycle / queries ---

/// `__res_close(*statp) -> ()` — close resolver state sockets. Stub
/// no-op since we don't manage sockets per-state.
///
/// # Safety
/// `statp` may be NULL; we don't dereference it.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_close(_statp: *mut c_void) {}

/// `__res_isourserver(*statp, *addr) -> int` — check if `*addr`
/// matches a configured nameserver. Stub returns 0 (not ours).
///
/// # Safety
/// Pointers may be NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_isourserver(_statp: *const c_void, _addr: *const c_void) -> c_int {
    0
}

/// `__res_nameinquery(name, type, class, *buf, eom) -> int` — public
/// alias of `__libc_res_nameinquery`. Stub returns 0 (not present).
///
/// # Safety
/// Pointers may be NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_nameinquery(
    _name: *const c_char,
    _type: c_int,
    _class: c_int,
    _buf: *const c_void,
    _eom: *const c_void,
) -> c_int {
    0
}

/// `__res_queriesmatch(buf1, eom1, buf2, eom2) -> int` — public alias
/// of `__libc_res_queriesmatch`. Stub returns 0.
///
/// # Safety
/// Pointers may be NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_queriesmatch(
    _buf1: *const c_void,
    _eom1: *const c_void,
    _buf2: *const c_void,
    _eom2: *const c_void,
) -> c_int {
    0
}

/// `__dn_count_labels(*name) -> int` — count labels in an encoded DNS
/// name (counts the dots in a decoded name; on encoded format counts
/// the length-prefixed segments). Returns -1 on bad input.
///
/// # Safety
/// `name` may be NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __dn_count_labels(name: *const c_char) -> c_int {
    let Some(s) = (unsafe { required_cstr_bytes(name) }) else {
        return -1;
    };
    if s.is_empty() {
        return 0;
    }
    let mut labels = 1i32;
    for &b in s {
        if b == b'.' {
            labels += 1;
        }
    }
    // A trailing dot (FQDN) counts as the root label, not an extra
    // separator — so subtract 1 if the name ended with `.`.
    if s.ends_with(b".") {
        labels -= 1;
    }
    labels
}

// --- /etc/hosts iteration ---
//
// These are the historical libresolv hooks for iterating /etc/hosts. They
// were superseded by the NSS files plugin (_nss_files_gethostent_r) which
// we already ship. Returning NULL/void from the legacy entries reports
// "no host table available", matching the contract for "fall back to NSS".

/// `_sethtent(stayopen) -> ()` — open or rewind /etc/hosts iteration.
/// Stub no-op.
///
/// # Safety
/// Trivially safe.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _sethtent(_stayopen: c_int) {}

/// `_gethtent() -> *struct hostent` — next /etc/hosts entry. Stub
/// returns NULL.
///
/// # Safety
/// Trivially safe.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _gethtent() -> *mut c_void {
    core::ptr::null_mut()
}

/// `_gethtbyname(*name) -> *struct hostent` — lookup name in
/// /etc/hosts.
///
/// # Safety
/// `name` may be NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _gethtbyname(name: *const c_char) -> *mut c_void {
    unsafe { _gethtbyname2(name, libc::AF_INET) }
}

/// `_gethtbyname2(*name, af) -> *struct hostent` — address-family-
/// constrained variant.
///
/// # Safety
/// `name` may be NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _gethtbyname2(name: *const c_char, af: c_int) -> *mut c_void {
    if af != libc::AF_UNSPEC && af != libc::AF_INET {
        unsafe { set_h_errnop(ptr::null_mut(), HOST_NOT_FOUND_ERRNO) };
        return core::ptr::null_mut();
    }

    let name_cstr = match unsafe { opt_cstr(name) } {
        Ok(Some(value)) => value,
        Ok(None) => {
            unsafe { set_h_errnop(ptr::null_mut(), HOST_NOT_FOUND_ERRNO) };
            return core::ptr::null_mut();
        }
        Err(()) => {
            unsafe { set_h_errnop(ptr::null_mut(), NO_RECOVERY_ERRNO) };
            return core::ptr::null_mut();
        }
    };
    let name_bytes = name_cstr.to_bytes();
    if name_bytes.is_empty() {
        unsafe { set_h_errnop(ptr::null_mut(), HOST_NOT_FOUND_ERRNO) };
        return core::ptr::null_mut();
    }

    let Some(addr) = lookup_hosts_ipv4_by_name(name_bytes) else {
        unsafe { set_h_errnop(ptr::null_mut(), HOST_NOT_FOUND_ERRNO) };
        return core::ptr::null_mut();
    };

    unsafe { set_h_errnop(ptr::null_mut(), 0) };
    unsafe { populate_tls_hostent(name_bytes, addr) }
}

/// `_gethtbyaddr(*addr, len, af) -> *struct hostent` — reverse
/// lookup in /etc/hosts.
///
/// # Safety
/// `addr` may be NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _gethtbyaddr(addr: *const c_void, len: c_int, af: c_int) -> *mut c_void {
    if addr.is_null()
        || af != libc::AF_INET
        || len < 4
        || !tracked_region_fits(addr, size_of::<libc::in_addr>())
    {
        unsafe { set_h_errnop(ptr::null_mut(), HOST_NOT_FOUND_ERRNO) };
        return core::ptr::null_mut();
    }

    let octets = unsafe { std::slice::from_raw_parts(addr.cast::<u8>(), 4) };
    let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    let ip_text = ip.to_string();
    let Ok(content) = read_hosts_backend() else {
        unsafe { set_h_errnop(ptr::null_mut(), HOST_NOT_FOUND_ERRNO) };
        return core::ptr::null_mut();
    };
    let hostnames = frankenlibc_core::resolv::reverse_lookup_hosts(&content, ip_text.as_bytes());
    let Some(hostname) = hostnames.first() else {
        unsafe { set_h_errnop(ptr::null_mut(), HOST_NOT_FOUND_ERRNO) };
        return core::ptr::null_mut();
    };

    unsafe { set_h_errnop(ptr::null_mut(), 0) };
    unsafe { populate_tls_hostent(hostname, ip) }
}
