//! Caller-owned `<resolv.h>` state and native reentrant resolver operations.
//!
//! The public layout is the glibc header ABI, not an opaque registry handle.
//! Every operation snapshots the caller's current fields before network I/O.
//! The registry owns only storage allocated by init; it never owns caller
//! overrides, socket descriptors, or locks held across a DNS exchange.

pub mod global;

use std::collections::BTreeMap;
use std::ffi::{OsString, c_char, c_int, c_ulong, c_void};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::ffi::OsStrExt;
use std::sync::Mutex;
use std::time::Duration;

use frankenlibc_core::dns_transport::{LookupConfig, QueryError, QueryOptions, raw};
use frankenlibc_core::resolv::config::{MAX_SORT_RULES, ResolverConfig, SortRule};
use frankenlibc_core::resolv::dns::{DNS_HEADER_SIZE, encode_domain_name};
use frankenlibc_core::resolv::dns_name::NS_MAXDNAME;

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::util::scan_c_string;

pub const RES_INIT: c_ulong = 1;
pub const RES_USEVC: c_ulong = 8;
pub const RES_IGNTC: c_ulong = 0x20;
pub const RES_RECURSE: c_ulong = 0x40;
pub const RES_DEFNAMES: c_ulong = 0x80;
pub const RES_DNSRCH: c_ulong = 0x200;
pub const RES_NOALIASES: c_ulong = 0x1000;
pub const RES_ROTATE: c_ulong = 0x4000;
pub const RES_USE_EDNS0: c_ulong = 0x0010_0000;
pub const RES_USE_DNSSEC: c_ulong = 0x0080_0000;
pub const RES_NOTLDQUERY: c_ulong = 0x0100_0000;
pub const RES_NORELOAD: c_ulong = 0x0200_0000;
pub const RES_TRUSTAD: c_ulong = 0x0400_0000;
pub const RES_NOAAAA: c_ulong = 0x0800_0000;
const RES_DEFAULT: c_ulong = RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;
const MAXNS: usize = 3;
const MAXDNSRCH: usize = 6;
const HOST_NOT_FOUND: c_int = 1;
const TRY_AGAIN: c_int = 2;
const NO_RECOVERY: c_int = 3;
const NO_DATA: c_int = 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SortEntry {
    pub addr: libc::in_addr,
    pub mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Extension {
    pub nscount: u16,
    pub nsmap: [u16; MAXNS],
    pub nssocks: [c_int; MAXNS],
    pub nscount6: u16,
    pub nsinit: u16,
    pub nsaddrs: [*mut libc::sockaddr_in6; MAXNS],
    pub reserved: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ExtensionUnion {
    pub pad: [u8; 52],
    pub ext: Extension,
}

/// Public glibc res_state layout, checked by the header/layout regressions.
/// `ndots_nsort` represents the public unsigned bitfield storage unit.
#[repr(C)]
pub struct State {
    pub retrans: c_int,
    pub retry: c_int,
    pub options: c_ulong,
    pub nscount: c_int,
    pub nsaddr_list: [libc::sockaddr_in; MAXNS],
    pub id: u16,
    pub dnsrch: [*mut c_char; MAXDNSRCH + 1],
    pub defdname: [c_char; 256],
    pub pfcode: c_ulong,
    pub ndots_nsort: u32,
    pub sort_list: [SortEntry; MAX_SORT_RULES],
    pub unused_qhook: *mut c_void,
    pub unused_rhook: *mut c_void,
    pub res_h_errno: c_int,
    pub vcsock: c_int,
    pub flags: u32,
    pub extension: ExtensionUnion,
}

impl State {
    pub fn zeroed() -> Self {
        // SAFETY: C scalar, byte-array and raw-pointer fields all admit zero.
        unsafe { std::mem::zeroed() }
    }

    fn sort_rules(&self) -> Vec<SortRule> {
        let shift = if cfg!(target_endian = "little") { 4 } else { 24 };
        let count = ((self.ndots_nsort >> shift) & 15) as usize;
        let mut rules: Vec<_> = self.sort_list
            .iter()
            .take(count)
            .map(|entry| SortRule {
                address: Ipv4Addr::from(entry.addr.s_addr.to_ne_bytes()),
                mask: Ipv4Addr::from(entry.mask.to_ne_bytes()),
            })
            .collect();
        // The public ABI only exposes ten preferences. Recover a longer
        // configured list while the caller still uses its published prefix.
        if count == MAX_SORT_RULES {
            let registry = OWNED.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(owned) = registry.get(&(self as *const Self as usize))
                && owned.sort_list.starts_with(&rules)
            {
                rules.extend_from_slice(&owned.sort_list[MAX_SORT_RULES..]);
            }
        }
        rules
    }

    fn ndots(&self) -> usize {
        if cfg!(target_endian = "little") {
            (self.ndots_nsort & 15) as usize
        } else {
            (self.ndots_nsort >> 28) as usize
        }
    }
}

struct OwnedState {
    sort_list: Vec<SortRule>,
    search: Vec<Box<[u8]>>,
    ipv6: Vec<(usize, Box<libc::sockaddr_in6>)>,
    published_search: [usize; MAXDNSRCH + 1],
    source: ConfigSource,
    /// Only ordinary host lookups enable automatic refresh. Explicit resolver
    /// initialization and caller-created states remain authoritative.
    host_refresh: Option<PublishedConfig>,
}

static OWNED: Mutex<BTreeMap<usize, OwnedState>> = Mutex::new(BTreeMap::new());

pub(crate) struct ForkGuard {
    _owned: std::sync::MutexGuard<'static, BTreeMap<usize, OwnedState>>,
}

/// Hold `OWNED` across `fork()` so a concurrent DNS lookup or thread teardown
/// cannot strand the mutex in the child process.
pub(crate) fn lock_for_fork() -> ForkGuard {
    ForkGuard {
        _owned: OWNED.lock().unwrap_or_else(|p| p.into_inner()),
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ConfigSource {
    content: Vec<u8>,
    localdomain: Option<OsString>,
    options: Option<OsString>,
}

impl ConfigSource {
    fn read() -> Self {
        Self {
            content: crate::resolv_abi::resolver_config_contents(),
            localdomain: crate::stdlib_abi::secure_var_os("LOCALDOMAIN"),
            options: crate::stdlib_abi::secure_var_os("RES_OPTIONS"),
        }
    }
}

#[derive(PartialEq, Eq)]
struct Ipv6Config {
    family: libc::sa_family_t,
    port: u16,
    flow: u32,
    address: [u8; 16],
    scope: u32,
}

impl From<&libc::sockaddr_in6> for Ipv6Config {
    fn from(address: &libc::sockaddr_in6) -> Self {
        Self {
            family: address.sin6_family,
            port: address.sin6_port,
            flow: address.sin6_flowinfo,
            address: address.sin6_addr.s6_addr,
            scope: address.sin6_scope_id,
        }
    }
}

/// Values published by initialization, excluding counters and error slots.
/// Pointer identity is checked before reading any pointee. Search comparisons
/// use the original allocation's exact length, including its terminator.
struct PublishedConfig {
    retrans: c_int,
    retry: c_int,
    options: c_ulong,
    nscount: c_int,
    ndots_nsort: u32,
    sort_list: [(u32, u32); MAX_SORT_RULES],
    ipv4: [(libc::sa_family_t, u16, u32); MAXNS],
    search_ptrs: [usize; MAXDNSRCH + 1],
    search_values: Vec<Vec<u8>>,
    ipv6_ptrs: [usize; MAXNS],
    ipv6_values: Vec<(usize, Ipv6Config)>,
}

impl PublishedConfig {
    fn capture(state: &State, owned: &OwnedState) -> Self {
        Self {
            retrans: state.retrans,
            retry: state.retry,
            options: state.options,
            nscount: state.nscount,
            ndots_nsort: state.ndots_nsort,
            sort_list: state.sort_list.map(|entry| (entry.addr.s_addr, entry.mask)),
            ipv4: state.nsaddr_list.map(|address| {
                (
                    address.sin_family,
                    address.sin_port,
                    address.sin_addr.s_addr,
                )
            }),
            search_ptrs: state.dnsrch.map(|pointer| pointer as usize),
            search_values: owned
                .search
                .iter()
                .take(MAXDNSRCH)
                .map(|name| name.to_vec())
                .collect(),
            // SAFETY: native initialization published the extension view.
            ipv6_ptrs: unsafe { state.extension.ext }
                .nsaddrs
                .map(|pointer| pointer as usize),
            ipv6_values: owned
                .ipv6
                .iter()
                .map(|(index, address)| (*index, Ipv6Config::from(address.as_ref())))
                .collect(),
        }
    }

    /// The matching OwnedState must remain locked/alive during this call.
    /// Its original buffers and the caller state own every matched pointer.
    unsafe fn unchanged(&self, state: &State) -> bool {
        // SAFETY: native initialization published this extension view.
        let extension = unsafe { state.extension.ext };
        if self.retrans != state.retrans
            || self.retry != state.retry
            || self.options != state.options
            || self.nscount != state.nscount
            || self.ndots_nsort != state.ndots_nsort
            || self.sort_list != state.sort_list.map(|entry| (entry.addr.s_addr, entry.mask))
            || self.ipv4
                != state.nsaddr_list.map(|address| {
                    (
                        address.sin_family,
                        address.sin_port,
                        address.sin_addr.s_addr,
                    )
                })
            || self.search_ptrs != state.dnsrch.map(|pointer| pointer as usize)
            || self.ipv6_ptrs != extension.nsaddrs.map(|pointer| pointer as usize)
        {
            return false;
        }
        for (index, expected) in self.search_values.iter().enumerate() {
            // SAFETY: identity matches an init-owned allocation or defdname
            // span, and the registry/caller keep the exact original span live.
            let actual = unsafe {
                std::slice::from_raw_parts(state.dnsrch[index].cast::<u8>(), expected.len())
            };
            if actual != expected {
                return false;
            }
        }
        for (index, expected) in &self.ipv6_values {
            // SAFETY: identity matches the still-live init-owned IPv6 box.
            let actual = unsafe { &*extension.nsaddrs[*index] };
            if &Ipv6Config::from(actual) != expected {
                return false;
            }
        }
        true
    }
}

/// Preserve the former per-lookup configuration refresh only while no caller
/// has taken control of the public state. The existing registry also owns this
/// eligibility, so close/teardown/address reuse cannot inherit it.
unsafe fn enable_host_refresh(pointer: *mut c_void) -> Result<(), c_int> {
    // SAFETY: called immediately after native initialization of this state.
    let state = unsafe { checked_state(pointer)? };
    let mut registry = OWNED.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(owned) = registry.get_mut(&(pointer as usize)) {
        owned.host_refresh = Some(PublishedConfig::capture(state, owned));
    }
    Ok(())
}

unsafe fn refresh_host_state(pointer: *mut c_void) -> Result<(), c_int> {
    // SAFETY: this thread owns its initialized state. Check before reading
    // the file or environment, since no-reload pins the current snapshot.
    if unsafe { checked_state(pointer)? }.options & RES_NORELOAD != 0 {
        return Ok(());
    }
    let eligible = OWNED
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(&(pointer as usize))
        .is_some_and(|owned| owned.host_refresh.is_some());
    if !eligible {
        return Ok(());
    }
    // No caller-state borrow or registry lock crosses filesystem/environment I/O.
    let source = ConfigSource::read();
    let reload = {
        // SAFETY: this thread exclusively owns the public state.
        let state = unsafe { checked_state(pointer)? };
        let mut registry = OWNED.lock().unwrap_or_else(|error| error.into_inner());
        let Some(owned) = registry.get_mut(&(pointer as usize)) else {
            return Ok(());
        };
        let Some(published) = &owned.host_refresh else {
            return Ok(());
        };
        // SAFETY: the lock keeps every original allocation alive. A changed
        // pointer returns false before any caller-installed pointee is read.
        if !unsafe { published.unchanged(state) } {
            owned.host_refresh = None;
            false
        } else {
            owned.source != source
        }
    };
    if reload {
        // Re-read inside init so the stored source always describes the exact
        // parsed image even if another process changes the file again.
        // SAFETY: only an unmodified state initialized by host lookup is reset.
        if unsafe { init_impl(pointer, false) } != 0 {
            // SAFETY: initialization published the caller's errno.
            return Err(unsafe { *crate::errno_abi::__errno_location() });
        }
        // SAFETY: the newly published state is still unmodified.
        unsafe { enable_host_refresh(pointer)? };
    }
    Ok(())
}

fn fits(address: usize, len: usize) -> bool {
    address != 0
        && len <= isize::MAX as usize
        && address.checked_add(len).is_some()
        && known_remaining(address).is_none_or(|remaining| len <= remaining)
}

unsafe fn checked_state<'a>(state: *mut c_void) -> Result<&'a mut State, c_int> {
    if !(state as usize).is_multiple_of(std::mem::align_of::<State>())
        || !fits(state as usize, std::mem::size_of::<State>())
    {
        return Err(libc::EINVAL);
    }
    // SAFETY: caller supplies a live, exclusively accessed res_state; the
    // null, alignment, integer span and known allocation extent are checked.
    Ok(unsafe { &mut *state.cast::<State>() })
}

/// Test an endpoint against a live public resolver state without initializing
/// or refreshing it. Configured wildcard addresses match any peer of the same
/// family and port; IPv6 flow/scope fields are not part of this legacy test.
///
/// # Safety
/// The state and family-sized address must remain readable during the call,
/// as must each non-null server pointer installed in the state.
pub(crate) unsafe fn is_our_server(pointer: *mut c_void, address: *const c_void) -> bool {
    fn object_fits<T>(pointer: *const T) -> bool {
        (pointer as usize).is_multiple_of(std::mem::align_of::<T>())
            && fits(pointer as usize, std::mem::size_of::<T>())
    }

    if !object_fits(pointer.cast::<State>()) || !object_fits(address.cast::<libc::sa_family_t>()) {
        return false;
    }
    // SAFETY: both objects are live for this call and their known extents and
    // alignments were checked. Shared borrows allow address to point into the
    // state's own nsaddr_list, a valid use of the public C interface.
    let state = unsafe { &*pointer.cast::<State>() };
    if !(0..=MAXNS as c_int).contains(&state.nscount) {
        return false;
    }
    // SAFETY: the aligned family field was checked above.
    let family = unsafe { *address.cast::<libc::sa_family_t>() } as c_int;
    let valid_peer = match family {
        libc::AF_INET => object_fits(address.cast::<libc::sockaddr_in>()),
        libc::AF_INET6 => object_fits(address.cast::<libc::sockaddr_in6>()),
        _ => false,
    };
    if !valid_peer {
        return false;
    }
    state.nsaddr_list[..state.nscount as usize]
        .iter()
        .enumerate()
        .any(|(index, inline)| {
            // A populated inline slot is authoritative even if an older
            // extension pointer remains. Only an unspecified inline family
            // selects extension storage, which may hold either IP family.
            let server = match inline.sin_family as c_int {
                libc::AF_INET => (inline as *const libc::sockaddr_in).cast::<c_void>(),
                libc::AF_UNSPEC => {
                    // SAFETY: index is bounded by the validated public count.
                    unsafe { state.extension.ext.nsaddrs[index] }.cast::<c_void>()
                }
                _ => return false,
            };
            if !object_fits(server.cast::<libc::sa_family_t>()) {
                return false;
            }
            // SAFETY: read only the checked family field before deciding how
            // large the selected sockaddr must be.
            if unsafe { *server.cast::<libc::sa_family_t>() } as c_int != family {
                return false;
            }
            match family {
                libc::AF_INET => {
                    if !object_fits(server.cast::<libc::sockaddr_in>()) {
                        return false;
                    }
                    // SAFETY: both complete IPv4 objects were checked.
                    let peer = unsafe { &*address.cast::<libc::sockaddr_in>() };
                    let server = unsafe { &*server.cast::<libc::sockaddr_in>() };
                    server.sin_port == peer.sin_port
                        && (server.sin_addr.s_addr == libc::INADDR_ANY
                            || server.sin_addr.s_addr == peer.sin_addr.s_addr)
                }
                libc::AF_INET6 => {
                    if !object_fits(server.cast::<libc::sockaddr_in6>()) {
                        return false;
                    }
                    // SAFETY: both complete IPv6 objects were checked.
                    let peer = unsafe { &*address.cast::<libc::sockaddr_in6>() };
                    let server = unsafe { &*server.cast::<libc::sockaddr_in6>() };
                    server.sin6_port == peer.sin6_port
                        && (server.sin6_addr.s6_addr == [0; 16]
                            || server.sin6_addr.s6_addr == peer.sin6_addr.s6_addr)
                }
                _ => false,
            }
        })
}

unsafe fn text(pointer: *const c_char) -> Result<Vec<u8>, c_int> {
    if pointer.is_null() {
        return Err(libc::EINVAL);
    }
    let limit = known_remaining(pointer as usize).map_or(NS_MAXDNAME, |n| n.min(NS_MAXDNAME));
    // SAFETY: a caller-owned C string, bounded by the name/known-buffer limit.
    let (length, terminated) = unsafe { scan_c_string(pointer, Some(limit)) };
    if !terminated {
        return Err(libc::EMSGSIZE);
    }
    // SAFETY: the scan established this readable span before the terminator.
    Ok(unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) }.to_vec())
}

/// Resolve an explicit alias using only the caller's option snapshot. This
/// does not initialize or mutate state, nor borrow it across filesystem I/O.
pub(crate) unsafe fn hostalias(pointer: *mut c_void, name: &[u8]) -> Option<Vec<u8>> {
    // SAFETY: caller-owned state is checked before its flags are copied.
    let options = unsafe { checked_state(pointer).ok()? }.options;
    crate::resolv_abi::hostalias_lookup(name, options)
}

fn fail(error: c_int) -> c_int {
    // SAFETY: errno is local to the calling thread.
    unsafe { set_abi_errno(error) };
    -1
}

fn transport_errno(error: &QueryError) -> c_int {
    match error {
        QueryError::InvalidQuery => libc::EINVAL,
        QueryError::InvalidResponse => libc::EMSGSIZE,
        QueryError::ResponseCode(_)
        | QueryError::ExtendedResponseCode(_)
        | QueryError::RetryableResponse(_) => libc::EAGAIN,
        QueryError::Io(error) => error.raw_os_error().unwrap_or_else(|| match error.kind() {
            ErrorKind::TimedOut | ErrorKind::WouldBlock => libc::ETIMEDOUT,
            ErrorKind::ConnectionRefused => libc::ECONNREFUSED,
            ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof => libc::ECONNRESET,
            ErrorKind::Interrupted => libc::EINTR,
            ErrorKind::PermissionDenied => libc::EACCES,
            ErrorKind::InvalidInput => libc::EINVAL,
            _ => libc::EIO,
        }),
    }
}

fn random_id() -> Result<u16, c_int> {
    let mut bytes = [0u8; 2];
    let mut done = 0;
    while done < bytes.len() {
        // SAFETY: getrandom writes only the remaining bytes of this local
        // array. The raw syscall does not call a host resolver or allocator.
        let result = unsafe {
            frankenlibc_core::syscall::syscall3(
                libc::SYS_getrandom as usize,
                bytes.as_mut_ptr().add(done) as usize,
                bytes.len() - done,
                0,
            )
        } as isize;
        if result == -(libc::EINTR as isize) {
            continue;
        }
        if result <= 0 {
            return Err(if result == 0 {
                libc::EIO
            } else {
                (-result) as c_int
            });
        }
        done += result as usize;
    }
    Ok(u16::from_ne_bytes(bytes))
}

fn initial_config(source: &ConfigSource) -> (ResolverConfig, c_ulong, [bool; 2], bool) {
    let ConfigSource {
        content,
        localdomain,
        options,
    } = source;
    let mut config = crate::resolv_abi::parse_resolver_config(content);
    config.apply_overrides(
        localdomain.as_ref().map(|value| value.as_bytes()),
        options.as_ref().map(|value| value.as_bytes()),
    );
    // Read the public res_state options from the same fresh file/environment
    // snapshot. Retain this API's existing tokenization while hostname
    // lookups also honor EDNS through ResolverConfig.
    // glibc accepts the "edns0" prefix and does not recognize "no-edns0".
    let mut edns0 = false;
    let mut explicit_timing = [false; 2];
    let mut explicit_no_aaaa = false;
    let mut observe_option = |word: &[u8]| {
        edns0 |= word.starts_with(b"edns0");
        explicit_no_aaaa |= word.starts_with(b"no-aaaa") || word.starts_with(b"-no-aaaa");
        for (index, prefix) in [b"timeout:".as_slice(), b"attempts:".as_slice()]
            .into_iter()
            .enumerate()
        {
            if let Some(value) = word.strip_prefix(prefix) {
                // Match the core config parser: a leading '+' is valid,
                // while empty, negative, nondecimal and overflowing values
                // do not override the legacy caller's nonzero timing.
                let digits = value.strip_prefix(b"+").unwrap_or(value);
                let valid = !digits.is_empty()
                    && digits
                        .iter()
                        .try_fold(0u32, |number, &byte| {
                            if byte.is_ascii_digit() {
                                number.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
                            } else {
                                None
                            }
                        })
                        .is_some();
                explicit_timing[index] |= valid;
            }
        }
    };
    for line in content.split(|&byte| byte == b'\n') {
        let mut words = line
            .split(u8::is_ascii_whitespace)
            .filter(|word| !word.is_empty());
        if words.next() != Some(b"options".as_slice()) {
            continue;
        }
        for word in words {
            observe_option(word);
        }
    }
    if let Some(options) = options {
        for word in options
            .as_bytes()
            .split(u8::is_ascii_whitespace)
            .filter(|part| !part.is_empty())
        {
            observe_option(word);
        }
    }
    (
        config,
        if edns0 { RES_USE_EDNS0 } else { 0 },
        explicit_timing,
        explicit_no_aaaa,
    )
}

/// Initialize a caller-owned state from a fresh configuration read. Never
/// reuse the process-global LazyLock: explicit reinitialization must see edits.
pub unsafe fn init(pointer: *mut c_void) -> c_int {
    // SAFETY: this entry has the same caller-owned-state preconditions.
    unsafe { init_impl(pointer, false) }
}

// The legacy global initializer preserves established options and nonzero
// timing unless the current configuration explicitly overrides that timing.
// Reentrant initialization starts fresh; both consume one config snapshot.
unsafe fn init_impl(pointer: *mut c_void, legacy_global: bool) -> c_int {
    // SAFETY: this function's caller supplies the C state described above.
    let state = match unsafe { checked_state(pointer) } {
        Ok(state) => state,
        Err(error) => return fail(error),
    };
    let source = ConfigSource::read();
    let (config, extended_options, explicit_timing, explicit_no_aaaa) = initial_config(&source);
    let id = if legacy_global || state.id == 0 {
        match random_id() {
            Ok(id) => id,
            Err(error) => return fail(error),
        }
    } else {
        state.id
    };
    let mut next = State::zeroed();
    next.retrans = if legacy_global && state.retrans != 0 && !explicit_timing[0] {
        state.retrans
    } else {
        config.timeout as c_int
    };
    next.retry = if legacy_global && state.retry != 0 && !explicit_timing[1] {
        state.retry
    } else {
        config.attempts as c_int
    };
    next.id = id;
    next.options = RES_INIT
        | extended_options
        | if legacy_global && state.options & RES_INIT != 0 {
            state.options
        } else {
            RES_DEFAULT
        };
    for (setting, flag) in [
        (config.no_tld_query, RES_NOTLDQUERY),
        (config.no_reload, RES_NORELOAD),
    ] {
        match setting {
            Some(true) => next.options |= flag,
            Some(false) => next.options &= !flag,
            None => {}
        }
    }
    if config.use_vc {
        next.options |= RES_USEVC;
    }
    if config.rotate {
        next.options |= RES_ROTATE;
    }
    if config.trust_ad {
        next.options |= RES_TRUSTAD;
    }
    if explicit_no_aaaa {
        next.options &= !RES_NOAAAA;
    }
    if config.no_aaaa {
        next.options |= RES_NOAAAA;
    }
    for (entry, rule) in next.sort_list.iter_mut().zip(&config.sort_list) {
        entry.addr.s_addr = u32::from_ne_bytes(rule.address.octets());
        entry.mask = u32::from_ne_bytes(rule.mask.octets());
    }
    let nsort = config.sort_list.len().min(MAX_SORT_RULES) as u32;
    next.ndots_nsort = if cfg!(target_endian = "little") {
        config.ndots.min(15) | (nsort << 4)
    } else {
        (config.ndots.min(15) << 28) | (nsort << 24)
    };
    next.vcsock = -1;
    let mut extension = Extension {
        nscount: 0,
        nsmap: [0, 1, 2],
        nssocks: [-1; MAXNS],
        nscount6: 0,
        nsinit: 0,
        nsaddrs: [std::ptr::null_mut(); MAXNS],
        reserved: [0; 2],
    };
    let mut owned = OwnedState {
        sort_list: Vec::new(),
        search: Vec::new(),
        ipv6: Vec::new(),
        published_search: [0; MAXDNSRCH + 1],
        source,
        host_refresh: None,
    };
    for index in 0..config.nameservers.len().min(MAXNS) {
        next.nscount += 1;
        match config.nameserver_endpoint(index) {
            SocketAddr::V4(endpoint) => {
                next.nsaddr_list[index].sin_family = libc::AF_INET as _;
                next.nsaddr_list[index].sin_port = endpoint.port().to_be();
                next.nsaddr_list[index].sin_addr.s_addr =
                    u32::from_ne_bytes(endpoint.ip().octets());
            }
            SocketAddr::V6(endpoint) => {
                // SAFETY: sockaddr_in6 consists entirely of zero-valid fields.
                let mut address: Box<libc::sockaddr_in6> = Box::new(unsafe { std::mem::zeroed() });
                address.sin6_family = libc::AF_INET6 as _;
                address.sin6_port = endpoint.port().to_be();
                address.sin6_addr.s6_addr = endpoint.ip().octets();
                address.sin6_scope_id = endpoint.scope_id();
                extension.nsaddrs[index] = &mut *address;
                extension.nscount6 += 1;
                owned.ipv6.push((index, address));
            }
        }
    }
    owned.sort_list = config.sort_list;
    for domain in &config.search {
        let mut bytes = domain.as_bytes().to_vec();
        if bytes.contains(&0) {
            continue;
        }
        bytes.push(0);
        owned.search.push(bytes.into_boxed_slice());
    }
    let mut inline_offset = 0;
    for (index, domain) in owned.search.iter_mut().take(MAXDNSRCH).enumerate() {
        if inline_offset + domain.len() <= next.defdname.len() {
            for (out, &byte) in next.defdname[inline_offset..inline_offset + domain.len()]
                .iter_mut()
                .zip(domain.iter())
            {
                *out = byte as c_char;
            }
            // SAFETY: the caller state stays at this address; publishing next
            // replaces bytes but does not move its inline domain buffer.
            next.dnsrch[index] = unsafe { state.defdname.as_mut_ptr().add(inline_offset) };
            inline_offset += domain.len();
        } else {
            next.dnsrch[index] = domain.as_mut_ptr().cast();
        }
        owned.published_search[index] = next.dnsrch[index] as usize;
    }
    next.extension.ext = extension;
    // Reinitialization replaces only allocations that this implementation
    // owns for this exact state address. No caller pointer is ever freed.
    let previous = OWNED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(pointer as usize, owned);
    *state = next;
    drop(previous);
    0
}

/// Release only this implementation's owned configuration storage. Overrides
/// installed by the caller stay borrowed. Exchanges retain no open sockets.
pub unsafe fn close(pointer: *mut c_void) {
    // SAFETY: a non-null caller state must remain valid during close.
    let Ok(state) = (unsafe { checked_state(pointer) }) else {
        return;
    };
    let owned = OWNED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(pointer as usize));
    if let Some(owned) = owned {
        for slot in &mut state.dnsrch {
            if owned
                .search
                .iter()
                .any(|name| std::ptr::eq(name.as_ptr().cast::<c_char>(), *slot))
            {
                *slot = std::ptr::null_mut();
            }
        }
        // SAFETY: the extension ABI has the layout in the public header.
        let extension = unsafe { &mut state.extension.ext };
        for (index, address) in &owned.ipv6 {
            if std::ptr::eq(extension.nsaddrs[*index], &**address) {
                extension.nsaddrs[*index] = std::ptr::null_mut();
            }
        }
        extension.nscount6 = extension.nsaddrs.iter().filter(|p| !p.is_null()).count() as u16;
        extension.nsinit = 0;
    }
    // Do not close descriptors found in an arbitrary caller-owned structure.
    // None were created by this stateless-per-exchange transport.
}

unsafe fn ensure_initialized(pointer: *mut c_void) -> Result<(), c_int> {
    // SAFETY: caller owns and exclusively accesses the state.
    if unsafe { checked_state(pointer)? }.options & RES_INIT == 0 && unsafe { init(pointer) } != 0 {
        // SAFETY: errno belongs to this thread and was set by init.
        return Err(unsafe { *crate::errno_abi::__errno_location() });
    }
    Ok(())
}

/// Owned configuration for one ordinary hostname or reverse lookup.
pub(crate) struct HostLookup {
    pub config: LookupConfig,
    pub options: QueryOptions,
    pub alias: Option<Vec<u8>>,
    pub sort_list: Vec<SortRule>,
}

unsafe fn host_lookup(pointer: *mut c_void, name: Option<&[u8]>) -> Result<HostLookup, c_int> {
    let (options, ndots, sort_list) = {
        // SAFETY: the global wrapper supplies this thread's live state.
        let state = unsafe { checked_state(pointer)? };
        (state.options, state.ndots() as u32, state.sort_rules())
    };
    // SAFETY: validate and copy complete endpoints before network I/O.
    let transport = unsafe { transport_config(pointer)? };
    let alias = name
        .filter(|name| !name.contains(&b'.'))
        .and_then(|name| crate::resolv_abi::hostalias_lookup(name, options));
    let search = if name.is_some() && alias.is_none() && options & (RES_DEFNAMES | RES_DNSRCH) != 0
    {
        // SAFETY: copies bounded strings while the caller owns them. Reverse
        // lookups and aliases never consult irrelevant search-list pointers.
        unsafe { search_domains(pointer)? }
    } else {
        Vec::new()
    };
    let query_options = QueryOptions {
        trust_ad: transport.trust_ad,
        use_vc: transport.use_vc,
        no_aaaa: transport.no_aaaa,
        edns0: options & RES_USE_EDNS0 != 0,
        recurse: options & RES_RECURSE != 0,
        dnssec: options & RES_USE_DNSSEC != 0,
        ignore_truncation: transport.ignore_truncation,
    };
    Ok(HostLookup {
        config: LookupConfig {
            transport,
            search,
            ndots: if alias.is_some() { 0 } else { ndots },
            defnames: alias.is_none() && options & RES_DEFNAMES != 0,
            dnsrch: alias.is_none() && options & RES_DNSRCH != 0,
            no_tld_query: alias.is_none() && options & RES_NOTLDQUERY != 0,
        },
        options: query_options,
        alias,
        sort_list,
    })
}

unsafe fn transport_config(pointer: *mut c_void) -> Result<raw::Config, c_int> {
    // SAFETY: checked state borrow ends when the snapshot is returned.
    let state = unsafe { checked_state(pointer)? };
    if !(0..=MAXNS as c_int).contains(&state.nscount) {
        return Err(libc::EINVAL);
    }
    let mut nameservers = Vec::with_capacity(state.nscount as usize);
    // SAFETY: this is the extension view of the public C union.
    let extension = unsafe { &state.extension.ext };
    for index in 0..state.nscount as usize {
        let v4 = &state.nsaddr_list[index];
        if v4.sin_family as c_int == libc::AF_INET {
            nameservers.push(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(v4.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(v4.sin_port),
            ));
        } else {
            let v6 = extension.nsaddrs[index];
            if !matches!(v4.sin_family as c_int, 0 | libc::AF_INET6)
                || !fits(v6 as usize, std::mem::size_of::<libc::sockaddr_in6>())
                || !(v6 as usize).is_multiple_of(std::mem::align_of::<libc::sockaddr_in6>())
            {
                return Err(libc::EINVAL);
            }
            // SAFETY: a caller-installed or init-owned sockaddr_in6 with
            // checked null/alignment/known extent; copied before any I/O.
            let address = unsafe { &*v6 };
            if address.sin6_family as c_int != libc::AF_INET6 {
                return Err(libc::EINVAL);
            }
            nameservers.push(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                u32::from_be(address.sin6_flowinfo),
                address.sin6_scope_id,
            )));
        }
    }
    Ok(raw::Config {
        nameservers,
        timeout: Duration::from_secs(state.retrans.max(1) as u64),
        attempts: state.retry.max(1) as u32,
        rotate: state.options & RES_ROTATE != 0,
        use_vc: state.options & RES_USEVC != 0,
        ignore_truncation: state.options & RES_IGNTC != 0,
        trust_ad: state.options & RES_TRUSTAD != 0,
        no_aaaa: state.options & RES_NOAAAA != 0,
    })
}

fn make_query(
    name: &[u8],
    op: c_int,
    class: c_int,
    kind: c_int,
    options: c_ulong,
) -> Result<Vec<u8>, c_int> {
    if !matches!(op, 0 | 4) || !(0..=65535).contains(&class) || !(0..=65535).contains(&kind) {
        return Err(libc::EINVAL);
    }
    let name = encode_domain_name(name).ok_or(libc::EMSGSIZE)?;
    let mut wire = vec![0; DNS_HEADER_SIZE];
    wire[..2].copy_from_slice(&random_id()?.to_ne_bytes());
    let flags = ((op as u16) << 11)
        | if options & RES_RECURSE != 0 { 0x100 } else { 0 }
        | if options & RES_TRUSTAD != 0 { 0x20 } else { 0 };
    wire[2..4].copy_from_slice(&flags.to_be_bytes());
    wire[5] = 1;
    wire.extend_from_slice(&name);
    wire.extend_from_slice(&(kind as u16).to_be_bytes());
    wire.extend_from_slice(&(class as u16).to_be_bytes());
    Ok(wire)
}

/// Build from this state's recursion/AD options without implicitly calling
/// init. A zero-initialized state intentionally emits neither RD nor AD.
#[allow(clippy::too_many_arguments)]
pub unsafe fn mkquery(
    pointer: *mut c_void,
    op: c_int,
    name: *const c_char,
    class: c_int,
    kind: c_int,
    data: *const c_void,
    _datalen: c_int,
    _newrr: *const c_void,
    buffer: *mut c_void,
    capacity: c_int,
) -> c_int {
    let result = (|| {
        // SAFETY: validated caller state and bounded C string inputs.
        let options = unsafe { checked_state(pointer)? }.options;
        let name = unsafe { text(name)? };
        let mut wire = make_query(&name, op, class, kind, options)?;
        if op == 4 && !data.is_null() {
            // NOTIFY's optional completion name is a NULL additional RR.
            let name = unsafe { text(data.cast())? };
            let name = encode_domain_name(&name).ok_or(libc::EMSGSIZE)?;
            wire[11] = 1;
            // The question name is already present. Compress the longest
            // matching label suffix, preserving binary label boundaries.
            let mut prefix = 0;
            let mut compressed = None;
            while prefix < name.len() && name[prefix] != 0 {
                let mut target = DNS_HEADER_SIZE;
                while target < wire.len() && wire[target] != 0 {
                    let mut end = target;
                    while wire[end] != 0 {
                        end += usize::from(wire[end]) + 1;
                    }
                    if name[prefix..].eq_ignore_ascii_case(&wire[target..=end]) {
                        compressed = Some((prefix, target));
                        break;
                    }
                    target += usize::from(wire[target]) + 1;
                }
                if compressed.is_some() {
                    break;
                }
                prefix += usize::from(name[prefix]) + 1;
            }
            if let Some((prefix, target)) = compressed {
                wire.extend_from_slice(&name[..prefix]);
                wire.extend_from_slice(&(0xc000 | target as u16).to_be_bytes());
            } else {
                wire.extend_from_slice(&name);
            }
            wire.extend_from_slice(&10u16.to_be_bytes());
            wire.extend_from_slice(&(class as u16).to_be_bytes());
            wire.extend_from_slice(&[0; 6]); // TTL=0, RDLENGTH=0.
        }
        if capacity < wire.len() as c_int || !fits(buffer as usize, capacity.max(0) as usize) {
            return Err(libc::EMSGSIZE);
        }
        // SAFETY: output capacity has been checked; all input C strings were
        // copied before writing, so input and output may overlap.
        unsafe { std::ptr::copy_nonoverlapping(wire.as_ptr(), buffer.cast(), wire.len()) };
        // SAFETY: checked state remains caller-owned throughout the operation.
        unsafe { checked_state(pointer)? }.id = u16::from_ne_bytes([wire[0], wire[1]]);
        Ok(wire.len() as c_int)
    })();
    result.unwrap_or_else(fail)
}

unsafe fn copy_reply(
    reply: &raw::Reply,
    answer: *mut c_void,
    capacity: c_int,
) -> Result<c_int, c_int> {
    if capacity < DNS_HEADER_SIZE as c_int || !fits(answer as usize, capacity.max(0) as usize) {
        return Err(libc::EINVAL);
    }
    // SAFETY: checked writable caller extent, with no live query-buffer borrow.
    let out = unsafe { std::slice::from_raw_parts_mut(answer.cast(), capacity as usize) };
    reply
        .copy_answer(out)
        .map(|n| n as c_int)
        .map_err(|e| transport_errno(&e))
}

/// Send using the caller's current nameservers (including ports and IPv6
/// scope), timeouts, retry count, rotation, TCP, truncation and trust flags.
pub unsafe fn send(
    pointer: *mut c_void,
    message: *const c_void,
    length: c_int,
    answer: *mut c_void,
    capacity: c_int,
) -> c_int {
    let result = (|| {
        if !(DNS_HEADER_SIZE as c_int..=65535).contains(&length)
            || capacity < DNS_HEADER_SIZE as c_int
            || !fits(message as usize, length.max(0) as usize)
            || !fits(answer as usize, capacity.max(0) as usize)
        {
            return Err(libc::EINVAL);
        }
        // SAFETY: all caller spans have been checked before initialization/I/O.
        unsafe { ensure_initialized(pointer)? };
        let config = unsafe { transport_config(pointer)? };
        let query = unsafe { std::slice::from_raw_parts(message.cast(), length as usize) };
        let reply = raw::send(query, &config).map_err(|e| transport_errno(&e))?;
        // SAFETY: raw::send has finished borrowing message, which may alias answer.
        unsafe { copy_reply(&reply, answer, capacity) }
    })();
    result.unwrap_or_else(fail)
}

#[derive(Clone, Copy)]
struct LookupFailure {
    host: c_int,
    os: c_int,
    servfail: bool,
}

unsafe fn record_host_error(pointer: *mut c_void, code: c_int) {
    // SAFETY: state was validated on entry; both error slots belong to this caller.
    unsafe {
        (*pointer.cast::<State>()).res_h_errno = code;
        *crate::resolv_abi::__h_errno_location() = code;
    }
}

unsafe fn lookup(
    pointer: *mut c_void,
    name: &[u8],
    class: c_int,
    kind: c_int,
    options: c_ulong,
    config: &raw::Config,
    capacity: c_int,
) -> Result<raw::Reply, LookupFailure> {
    let mut wire = make_query(name, 0, class, kind, options).map_err(|os| LookupFailure {
        host: NO_RECOVERY,
        os,
        servfail: false,
    })?;
    if options & (RES_USE_EDNS0 | RES_USE_DNSSEC) != 0 {
        // RFC 6891 OPT: root owner, TYPE=41, CLASS=UDP payload, extended
        // RCODE/version zero, flags, empty option data. make_query produced
        // one question and no additional records, so exactly one OPT follows.
        // Match the live glibc query contract: at least 512, at most 1200;
        // capacity is already validated and is NOT used to allocate memory.
        let payload = capacity.clamp(512, 1200) as u16;
        let flags: u16 = if options & RES_USE_DNSSEC != 0 {
            0x8000
        } else {
            0
        };
        wire[11] = 1;
        wire.extend_from_slice(&[0, 0, 41]);
        wire.extend_from_slice(&payload.to_be_bytes());
        wire.extend_from_slice(&[0, 0]); // Extended RCODE=0, EDNS version=0.
        wire.extend_from_slice(&flags.to_be_bytes());
        wire.extend_from_slice(&[0, 0]); // RDLENGTH=0.
    }
    // Only query/querydomain/search synthesize EDNS. mkquery and raw send
    // retain their packet contract. In particular, retries never remove DO
    // or downgrade a caller's explicit DNSSEC request. DO requests records;
    // it does not authenticate them or relax the existing RES_TRUSTAD policy.
    // SAFETY: each public entry validated the caller state before lookup.
    unsafe { (*pointer.cast::<State>()).id = u16::from_ne_bytes([wire[0], wire[1]]) };
    raw::send_for_query(&wire, config).map_err(|error| LookupFailure {
        host: if matches!(
            error,
            QueryError::InvalidQuery | QueryError::InvalidResponse
        ) {
            NO_RECOVERY
        } else {
            TRY_AGAIN
        },
        os: transport_errno(&error),
        servfail: false,
    })
}

fn reply_status(reply: &raw::Reply) -> Result<(), LookupFailure> {
    let code = reply.packet[3] & 15;
    let host = match code {
        0 if reply.packet[6] != 0 || reply.packet[7] != 0 => return Ok(()),
        0 => NO_DATA,
        2 => TRY_AGAIN,
        3 => HOST_NOT_FOUND,
        _ => NO_RECOVERY,
    };
    Err(LookupFailure {
        host,
        os: 0,
        servfail: code == 2,
    })
}

unsafe fn finish_lookup(
    pointer: *mut c_void,
    result: Result<raw::Reply, LookupFailure>,
    answer: *mut c_void,
    capacity: c_int,
) -> c_int {
    match result {
        Ok(reply) => {
            // A valid negative DNS packet is still copied for the caller.
            // SAFETY: caller output and state remain live through this call.
            match unsafe { copy_reply(&reply, answer, capacity) } {
                Err(error) => {
                    unsafe { record_host_error(pointer, NO_RECOVERY) };
                    fail(error)
                }
                Ok(length) => match reply_status(&reply) {
                    // h_errno is meaningful on failure; a successful query
                    // preserves both preexisting error slots, like glibc.
                    Ok(()) => length,
                    Err(error) => {
                        unsafe { record_host_error(pointer, error.host) };
                        -1
                    }
                },
            }
        }
        Err(error) => {
            // SAFETY: caller's validated state and thread-local error slot.
            unsafe { record_host_error(pointer, error.host) };
            if error.os != 0 { fail(error.os) } else { -1 }
        }
    }
}

unsafe fn lookup_inputs(
    pointer: *mut c_void,
    answer: *mut c_void,
    capacity: c_int,
) -> Result<(raw::Config, c_ulong), c_int> {
    if capacity < DNS_HEADER_SIZE as c_int || !fits(answer as usize, capacity.max(0) as usize) {
        return Err(libc::EINVAL);
    }
    // SAFETY: validates and initializes the exclusively accessed caller state.
    unsafe { ensure_initialized(pointer)? };
    let config = unsafe { transport_config(pointer)? };
    let options = unsafe { checked_state(pointer)? }.options;
    Ok((config, options))
}

pub unsafe fn query(
    pointer: *mut c_void,
    name: *const c_char,
    class: c_int,
    kind: c_int,
    answer: *mut c_void,
    capacity: c_int,
) -> c_int {
    // SAFETY: validate before updating per-state errors or touching output.
    let (config, options) = match unsafe { lookup_inputs(pointer, answer, capacity) } {
        Ok(inputs) => inputs,
        Err(error) => return fail(error),
    };
    let result = match unsafe { text(name) } {
        Ok(name) => unsafe { lookup(pointer, &name, class, kind, options, &config, capacity) },
        Err(os) => Err(LookupFailure {
            host: NO_RECOVERY,
            os,
            servfail: false,
        }),
    };
    // SAFETY: spans were checked by lookup_inputs, with no retained input borrow.
    unsafe { finish_lookup(pointer, result, answer, capacity) }
}

pub unsafe fn querydomain(
    pointer: *mut c_void,
    name: *const c_char,
    domain: *const c_char,
    class: c_int,
    kind: c_int,
    answer: *mut c_void,
    capacity: c_int,
) -> c_int {
    // SAFETY: validate before updating per-state errors or touching output.
    let (config, options) = match unsafe { lookup_inputs(pointer, answer, capacity) } {
        Ok(inputs) => inputs,
        Err(error) => return fail(error),
    };
    let combined = (|| {
        // SAFETY: caller supplies NUL-terminated input strings; copies own bytes.
        let mut name = unsafe { text(name)? };
        if !domain.is_null() {
            let suffix = unsafe { text(domain)? };
            if !suffix.is_empty() {
                name.push(b'.');
                name.extend_from_slice(&suffix);
            }
        }
        Ok::<_, c_int>(name)
    })();
    let result = match combined {
        Ok(name) => unsafe { lookup(pointer, &name, class, kind, options, &config, capacity) },
        Err(os) => Err(LookupFailure {
            host: NO_RECOVERY,
            os,
            servfail: false,
        }),
    };
    // SAFETY: checked writable output and caller state; strings no longer borrowed.
    unsafe { finish_lookup(pointer, result, answer, capacity) }
}

unsafe fn search_domains(pointer: *mut c_void) -> Result<Vec<Vec<u8>>, c_int> {
    // SAFETY: the state and installed search strings remain caller-owned.
    let state = unsafe { checked_state(pointer)? };
    let published = state.dnsrch.map(|p| p as usize);
    let mut domains = Vec::new();
    for &domain in state.dnsrch.iter().take(MAXDNSRCH) {
        if domain.is_null() {
            break;
        }
        domains.push(unsafe { text(domain)? });
    }
    let registry = OWNED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(owned) = registry.get(&(pointer as usize))
        && owned.published_search == published
        && domains.iter().zip(&owned.search).all(|(domain, bytes)| {
            bytes.len() == domain.len() + 1 && bytes[..domain.len()] == domain[..]
        })
    {
        // A changed public pointer OR changed inline string invalidates the
        // extended suffix list. Ordinary caller overrides are authoritative.
        for bytes in owned.search.iter().skip(MAXDNSRCH) {
            let end = bytes.iter().position(|&b| b == 0).ok_or(libc::EINVAL)?;
            domains.push(bytes[..end].to_vec());
        }
    }
    Ok(domains)
}

pub unsafe fn search(
    pointer: *mut c_void,
    name: *const c_char,
    class: c_int,
    kind: c_int,
    answer: *mut c_void,
    capacity: c_int,
) -> c_int {
    // SAFETY: validate before updating errors or touching output.
    let (config, options) = match unsafe { lookup_inputs(pointer, answer, capacity) } {
        Ok(inputs) => inputs,
        Err(error) => return fail(error),
    };
    // res_nsearch starts with HOST_NOT_FOUND, unlike plain res_nquery.
    unsafe { record_host_error(pointer, HOST_NOT_FOUND) };
    let inputs = (|| {
        // SAFETY: bounded name/search copies; no caller memory is borrowed during I/O.
        let name = unsafe { text(name)? };
        let alias = if name.contains(&b'.') {
            None
        } else {
            crate::resolv_abi::hostalias_lookup(&name, options)
        };
        // An alias is a direct query: even caller-installed search pointers
        // are irrelevant and must not be read on this path.
        let domains = if alias.is_some() {
            Vec::new()
        } else {
            unsafe { search_domains(pointer)? }
        };
        let ndots = unsafe { checked_state(pointer)? }.ndots();
        Ok::<_, c_int>((name, alias, domains, ndots))
    })();
    let (name, alias, domains, ndots) = match inputs {
        Ok(inputs) => inputs,
        Err(os) => {
            return unsafe {
                finish_lookup(
                    pointer,
                    Err(LookupFailure {
                        host: NO_RECOVERY,
                        os,
                        servfail: false,
                    }),
                    answer,
                    capacity,
                )
            };
        }
    };
    if let Some(alias) = alias {
        // The first alias target is authoritative, including negative and
        // temporary replies. Do not search the original name on failure.
        return unsafe {
            finish_lookup(
                pointer,
                lookup(pointer, &alias, class, kind, options, &config, capacity),
                answer,
                capacity,
            )
        };
    }
    // Use wire labels to distinguish a final root dot from an escaped literal
    // dot. A decimal escaped dot is data, never a search-label separator.
    let mut escaped = false;
    let mut dots = 0;
    let mut absolute = false;
    for &byte in &name {
        absolute = false;
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            continue;
        }
        if byte == b'.' {
            dots += 1;
            absolute = true;
        }
    }
    if absolute {
        return unsafe {
            finish_lookup(
                pointer,
                lookup(pointer, &name, class, kind, options, &config, capacity),
                answer,
                capacity,
            )
        };
    }
    let first_bare = dots >= ndots;
    let use_search = if dots == 0 {
        options & RES_DEFNAMES != 0
    } else {
        options & RES_DNSRCH != 0
    };
    let mut candidates = Vec::new();
    if first_bare {
        candidates.push((name.clone(), true));
    }
    if use_search {
        for domain in domains {
            let mut candidate = name.clone();
            if domain != b"." && !domain.is_empty() {
                candidate.push(b'.');
                candidate.extend_from_slice(&domain);
            }
            candidates.push((candidate, false));
            if options & RES_DNSRCH == 0 {
                break;
            }
        }
    }
    if !first_bare && (dots != 0 || options & RES_NOTLDQUERY == 0 || candidates.is_empty()) {
        candidates.push((name.clone(), true));
    }
    let mut first_failure = None;
    let mut saved_nodata = false;
    let mut saved_servfail = false;
    let mut stop_search = false;
    let mut root_searched = false;
    let mut last_reply = None;
    let mut last_failure = LookupFailure {
        host: HOST_NOT_FOUND,
        os: 0,
        servfail: false,
    };
    for (candidate, bare) in candidates {
        if stop_search && !bare {
            continue;
        }
        if bare && root_searched {
            continue;
        }
        root_searched |= !bare && candidate == name;
        let result =
            unsafe { lookup(pointer, &candidate, class, kind, options, &config, capacity) };
        let failure = match result {
            Ok(reply) => match reply_status(&reply) {
                Ok(()) => return unsafe { finish_lookup(pointer, Ok(reply), answer, capacity) },
                Err(error) => {
                    last_reply = Some(reply);
                    error
                }
            },
            Err(error) => {
                last_reply = None;
                error
            }
        };
        // Each failed nquery updates h_errno even if a later candidate wins.
        unsafe { record_host_error(pointer, failure.host) };
        if first_bare && bare {
            first_failure = Some(failure);
        }
        if !bare {
            saved_nodata |= failure.host == NO_DATA;
            saved_servfail |= failure.servfail;
            if !matches!(failure.host, HOST_NOT_FOUND | NO_DATA) && !failure.servfail {
                stop_search = true;
            }
        }
        last_failure = failure;
        if failure.os == libc::ECONNREFUSED {
            break;
        }
    }
    let failure = if last_failure.os == libc::ECONNREFUSED {
        last_failure
    } else if let Some(first) = first_failure {
        first
    } else if saved_nodata {
        LookupFailure {
            host: NO_DATA,
            os: 0,
            servfail: false,
        }
    } else if saved_servfail {
        LookupFailure {
            host: TRY_AGAIN,
            os: 0,
            servfail: true,
        }
    } else {
        last_failure
    };
    if let Some(reply) = last_reply {
        // SAFETY: the checked output receives the last valid negative packet.
        if let Err(error) = unsafe { copy_reply(&reply, answer, capacity) } {
            return fail(error);
        }
    }
    // SAFETY: caller state was validated before constructing any query.
    unsafe { finish_lookup(pointer, Err(failure), answer, capacity) }
}
