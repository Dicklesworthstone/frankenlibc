//! Dynamically loaded NSS service modules (`libnss_<service>.so.2`).
//!
//! glibc resolves every nsswitch.conf source other than its built-in ones by
//! loading `libnss_<service>.so.2` and calling `_nss_<service>_<function>`
//! entry points (the public module ABI documented in the GNU libc manual,
//! "Adding another Service to NSS"). That is how `sss` (SSSD/LDAP/AD),
//! `systemd` (DynamicUser, systemd-homed), `winbind`, `ldap`, `mymachines`,
//! `extrausers` and friends provide users and groups. fl used to read
//! `/etc/passwd` and `/etc/group` only, so on any host configured with such a
//! source those users and groups did not exist under fl.
//!
//! This module owns the mechanics: reading nsswitch.conf (cached by file
//! fingerprint), loading modules once per process, and copying reentrant
//! callback results into fl's owned entry types. Calls that own their scratch
//! budget grow it on ERANGE. The policy -- source order, status actions, group
//! merge, initgroups de-duplication -- lives in `frankenlibc_core::nss`.
//! Hosts use the same module loader with `addrinfo::hosts_policy` for source
//! order and actions. Forward/reverse hostent results, aliases, address lists,
//! and the gethostbyname3_r canonical-name extension are copied before release.
//! gethostbyname4_r tuples retain mixed address families and IPv6 scope IDs.
//! Netgroups retain each selected module's set/get/end cursor, resolve nested
//! names through the captured source policy, and preserve NULL wildcards.
//! Public enumeration uses the caller's exact buffer budget; independent
//! membership queries use GNU's fixed 1024-byte module buffer.
//!
//! Interpose builds retain the host loader's module and allocator namespace.
//! Standalone builds use the owned loader and its matching allocation exports;
//! an unsupported object remains unavailable without falling back to the host.

use std::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::mem::{MaybeUninit, size_of};
use std::sync::{Arc, Mutex};

use frankenlibc_core::nss::{Answer, Database, Service, SourceKind, Status};

const NSSWITCH_PATH: &str = "/etc/nsswitch.conf";
const NSSWITCH_PATH_ENV: &str = "FRANKENLIBC_NSSWITCH_CONF";

/// Initial capacity for module calls that own their scratch budget.
const INITIAL_SCRATCH: usize = 1024;
/// Maximum growth for internally owned module scratch buffers.
const MAX_SCRATCH: usize = 1 << 24;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    len: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ino: u64,
}

struct ConfigCache {
    path: Vec<u8>,
    fingerprint: Option<Fingerprint>,
    /// Whether `fingerprint`/`parsed` describe the current `path` at all.
    loaded: bool,
    /// Source lists per database, parsed from the cached image.
    parsed: [Option<Arc<Vec<Service>>>; 7],
    /// Whether the image has its own `initgroups:` line.
    initgroups_explicit: Option<bool>,
    /// Process-local overrides are independent of the on-disk image. A
    /// fingerprint or path change must never erase an explicit selection.
    overrides: [Option<Arc<Vec<Service>>>; 7],
    hosts_override: Option<Arc<frankenlibc_core::addrinfo::hosts_policy::HostsPolicy>>,
    hosts_parsed: Option<Arc<frankenlibc_core::addrinfo::hosts_policy::HostsPolicy>>,
    /// GNU freezes the whole configuration on the first successful runtime
    /// override, even for databases that have not been queried yet.
    frozen: bool,
    snapshot: Option<Vec<u8>>,
}

static CONFIG: Mutex<ConfigCache> = Mutex::new(ConfigCache {
    path: Vec::new(),
    fingerprint: None,
    loaded: false,
    parsed: [None, None, None, None, None, None, None],
    initgroups_explicit: None,
    overrides: [None, None, None, None, None, None, None],
    hosts_override: None,
    hosts_parsed: None,
    frozen: false,
    snapshot: None,
});

pub(crate) enum ConfigureError {
    UnknownDatabase,
    InvalidServiceLine,
}

/// Install an immutable service-list snapshot for a supported database.
/// Parse before taking the cache lock: a rejected replacement leaves the old
/// selection intact, and lookups already holding an Arc finish on that image.
pub(crate) fn configure_lookup(database: &[u8], line: &[u8]) -> Result<(), ConfigureError> {
    if database == b"hosts" {
        let policy = frankenlibc_core::addrinfo::hosts_policy::HostsPolicy::from_service_line(line)
            .map_err(|_| ConfigureError::InvalidServiceLine)?;
        with_current_config(|cache, read| {
            freeze_config(cache, read);
            cache.hosts_override = Some(Arc::new(policy));
        });
        return Ok(());
    }
    let database = match database {
        b"passwd" => Database::Passwd,
        b"group" => Database::Group,
        b"shadow" => Database::Shadow,
        b"initgroups" => Database::Initgroups,
        b"publickey" => Database::Publickey,
        b"services" => Database::Services,
        b"netgroup" => Database::Netgroup,
        _ => return Err(ConfigureError::UnknownDatabase),
    };
    let services = frankenlibc_core::nss::parse_sources(line)
        .map_err(|_| ConfigureError::InvalidServiceLine)?;
    with_current_config(|cache, read| {
        freeze_config(cache, read);
        cache.overrides[database_slot(database)] = Some(Arc::new(services));
        // Implicit initgroups follows later group overrides. Shadow's fallback
        // comes from the configuration file, not a runtime passwd override.
        if database == Database::Group {
            cache.parsed[database_slot(Database::Initgroups)] = None;
        }
    });
    Ok(())
}

fn freeze_config(cache: &mut ConfigCache, read: fn(&ConfigCache) -> Option<Vec<u8>>) {
    if !cache.frozen {
        cache.snapshot = read(cache);
        cache.frozen = true;
        cache.parsed = [None, None, None, None, None, None, None];
        cache.initgroups_explicit = None;
        cache.hosts_parsed = None;
    }
}

/// Hosts and accounts share one configuration image and override lifetime.
pub(crate) fn hosts_policy() -> Arc<frankenlibc_core::addrinfo::hosts_policy::HostsPolicy> {
    with_current_config(|cache, read| {
        if let Some(policy) = cache
            .hosts_override
            .as_ref()
            .or(cache.hosts_parsed.as_ref())
        {
            return Arc::clone(policy);
        }
        let policy = Arc::new(
            read(cache)
                .and_then(|content| {
                    frankenlibc_core::addrinfo::hosts_policy::HostsPolicy::parse(&content).ok()
                })
                .unwrap_or_default(),
        );
        cache.hosts_parsed = Some(Arc::clone(&policy));
        policy
    })
}

fn database_slot(database: Database) -> usize {
    match database {
        Database::Passwd => 0,
        Database::Group => 1,
        Database::Shadow => 2,
        Database::Initgroups => 3,
        Database::Publickey => 4,
        Database::Services => 5,
        Database::Netgroup => 6,
    }
}

fn config_path() -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    std::env::var_os(NSSWITCH_PATH_ENV)
        .filter(|v| !v.is_empty())
        .map(|v| v.as_bytes().to_vec())
        .unwrap_or_else(|| NSSWITCH_PATH.as_bytes().to_vec())
}

fn fingerprint(path: &[u8]) -> Option<Fingerprint> {
    let mut cpath = path.to_vec();
    cpath.push(0);
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: cpath is NUL-terminated; st is writable stat storage.
    unsafe {
        frankenlibc_core::syscall::sys_newfstatat(
            libc::AT_FDCWD,
            cpath.as_ptr(),
            st.as_mut_ptr().cast::<u8>(),
            0,
        )
    }
    .ok()?;
    // SAFETY: the syscall succeeded, so the stat buffer is initialized.
    let st = unsafe { st.assume_init() };
    Some(Fingerprint {
        len: st.st_size as u64,
        mtime_sec: st.st_mtime,
        mtime_nsec: st.st_mtime_nsec,
        ino: st.st_ino,
    })
}

/// The configured sources for `database`. nsswitch.conf is re-read and
/// re-parsed whenever its fingerprint changes until the first successful
/// runtime override freezes the image. A missing or unreadable file means the
/// built-in default (`nis nisplus` for publickey and `files` for accounts).
pub(crate) fn services(database: Database) -> Arc<Vec<Service>> {
    with_current_config(|cache, read| configured_services(cache, read, database))
}

fn configured_services(
    cache: &mut ConfigCache,
    read: fn(&ConfigCache) -> Option<Vec<u8>>,
    database: Database,
) -> Arc<Vec<Service>> {
    let slot = database_slot(database);
    if let Some(selected) = &cache.overrides[slot] {
        return Arc::clone(selected);
    }
    if let Some(parsed) = &cache.parsed[slot] {
        return Arc::clone(parsed);
    }
    let content = read(cache);
    let fallback = match database {
        Database::Initgroups => {
            // Derive sources and the SUCCESS rule from the same file read,
            // including before a runtime override freezes the image.
            let explicit = frankenlibc_core::nss::has_database_line(content.as_deref(), database);
            cache.initgroups_explicit = Some(explicit);
            (!explicit).then_some(Database::Group)
        }
        _ => None,
    };
    if let Some(fallback) = fallback
        && let Some(selected) = &cache.overrides[database_slot(fallback)]
    {
        let selected = Arc::clone(selected);
        cache.parsed[slot] = Some(Arc::clone(&selected));
        return selected;
    }
    let parsed = Arc::new(frankenlibc_core::nss::services_for(
        content.as_deref(),
        database,
    ));
    cache.parsed[slot] = Some(Arc::clone(&parsed));
    parsed
}

/// Snapshot the initgroups sources and their SUCCESS-action rule together.
/// A concurrent override must not combine an old source list with the new
/// list's explicit/implicit policy.
pub(crate) fn initgroups_policy() -> (Arc<Vec<Service>>, bool) {
    with_current_config(|cache, read| {
        let services = configured_services(cache, read, Database::Initgroups);
        if cache.overrides[database_slot(Database::Initgroups)].is_some() {
            return (services, true);
        }
        // configured_services publishes this flag alongside a parsed list.
        let explicit = cache.initgroups_explicit.unwrap_or(false);
        (services, explicit)
    })
}

/// Run `f` on the configuration cache after revalidating it against the
/// file's current fingerprint. `f` gets a reader for the file image.
fn with_current_config<R>(
    f: impl FnOnce(&mut ConfigCache, fn(&ConfigCache) -> Option<Vec<u8>>) -> R,
) -> R {
    let path = config_path();
    let now = fingerprint(&path);
    let mut cache = CONFIG.lock().unwrap_or_else(|e| e.into_inner());
    if !cache.frozen && !(cache.loaded && cache.path == path && cache.fingerprint == now) {
        cache.path = path;
        cache.fingerprint = now;
        cache.loaded = true;
        cache.parsed = [None, None, None, None, None, None, None];
        cache.initgroups_explicit = None;
        cache.hosts_parsed = None;
    }
    fn read(cache: &ConfigCache) -> Option<Vec<u8>> {
        use std::os::unix::ffi::OsStrExt;
        if cache.frozen {
            return cache.snapshot.clone();
        }
        cache.fingerprint?;
        std::fs::read(std::ffi::OsStr::from_bytes(&cache.path)).ok()
    }
    f(&mut cache, read)
}

/// True when `services` is exactly the native files source, the default and
/// by far the most common configuration: callers keep their cached files fast
/// paths and never touch the module machinery.
pub(crate) fn is_files_only(services: &[Service]) -> bool {
    matches!(services, [only] if only.kind() == SourceKind::Files)
}

// ---------------------------------------------------------------------------
// Module loading
// ---------------------------------------------------------------------------

struct LoadedModule {
    service: Vec<u8>,
    /// Selected loader's handle; 0 when the module could not be loaded.
    handle: usize,
    /// Resolved entry points (function name, address; 0 = absent).
    symbols: Vec<(&'static str, usize)>,
}

static MODULES: Mutex<Vec<LoadedModule>> = Mutex::new(Vec::new());

#[cfg(not(feature = "standalone"))]
fn module_dlopen(path: &CStr) -> usize {
    type DlopenFn = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
    let Some(addr) = crate::host_resolve::resolve_host_symbol_raw("dlopen") else {
        return 0;
    };
    // SAFETY: the host loader's dlopen has this signature.
    let dlopen: DlopenFn = unsafe { core::mem::transmute(addr) };
    // SAFETY: path is a valid C string.
    unsafe { dlopen(path.as_ptr(), libc::RTLD_LAZY) as usize }
}

#[cfg(feature = "standalone")]
fn module_dlopen(path: &CStr) -> usize {
    // SAFETY: path is a live C string. The standalone public loader owns
    // both the mapping and its dependencies and never delegates to the host.
    unsafe { crate::dlfcn_abi::dlopen(path.as_ptr(), libc::RTLD_LAZY) as usize }
}

#[cfg(not(feature = "standalone"))]
fn module_dlsym(handle: usize, name: &CStr) -> usize {
    type DlsymFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
    let Some(addr) = crate::host_resolve::resolve_host_symbol_raw("dlsym") else {
        return 0;
    };
    // SAFETY: the host loader's dlsym has this signature.
    let dlsym: DlsymFn = unsafe { core::mem::transmute(addr) };
    // SAFETY: handle came from the host dlopen (or is RTLD_DEFAULT); name is a C string.
    unsafe { dlsym(handle as *mut c_void, name.as_ptr()) as usize }
}

#[cfg(feature = "standalone")]
fn module_dlsym(handle: usize, name: &CStr) -> usize {
    // SAFETY: handles come from the same owned loader and name is a C string.
    unsafe { crate::dlfcn_abi::dlsym(handle as *mut c_void, name.as_ptr()) as usize }
}

fn valid_service_name(service: &[u8]) -> bool {
    !service.is_empty()
        && service.len() <= 64
        && service
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-' | b'.'))
}

/// Address of `_nss_<service>_<function>`, loading the module on first use.
/// `None` when the module or the entry point does not exist.
///
/// The table lock is never held across `dlopen`/`dlsym`: a module's
/// constructor may itself use the name service.
fn module_function(service: &[u8], function: &'static str) -> Option<usize> {
    if !valid_service_name(service) {
        return None;
    }
    let handle = {
        let modules = MODULES.lock().unwrap_or_else(|e| e.into_inner());
        match modules.iter().find(|m| m.service == service) {
            Some(module) if module.handle == 0 => return None,
            Some(module) => {
                if let Some(&(_, addr)) = module.symbols.iter().find(|(n, _)| *n == function) {
                    return (addr != 0).then_some(addr);
                }
                Some(module.handle)
            }
            None => None,
        }
    };
    let handle = handle.unwrap_or_else(|| {
        let mut path = b"libnss_".to_vec();
        path.extend_from_slice(service);
        path.extend_from_slice(b".so.2\0");
        let opened = CStr::from_bytes_with_nul(&path).map_or(0, module_dlopen);
        let mut modules = MODULES.lock().unwrap_or_else(|e| e.into_inner());
        match modules.iter().find(|m| m.service == service) {
            // Another thread won the race; its handle names the same object.
            Some(module) => module.handle,
            None => {
                modules.push(LoadedModule {
                    service: service.to_vec(),
                    handle: opened,
                    symbols: Vec::new(),
                });
                opened
            }
        }
    });
    if handle == 0 {
        return None;
    }
    let mut symbol = b"_nss_".to_vec();
    symbol.extend_from_slice(service);
    symbol.push(b'_');
    symbol.extend_from_slice(function.as_bytes());
    symbol.push(0);
    let addr = CStr::from_bytes_with_nul(&symbol).map_or(0, |name| module_dlsym(handle, name));
    let mut modules = MODULES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(module) = modules.iter_mut().find(|m| m.service == service)
        && !module.symbols.iter().any(|(n, _)| *n == function)
    {
        module.symbols.push((function, addr));
    }
    (addr != 0).then_some(addr)
}

/// Whether the module for `service` has already been loaded (successfully).
/// Used by `end*ent`, which must not load a module just to close it.
fn module_loaded(service: &[u8]) -> bool {
    MODULES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|m| m.service == service && m.handle != 0)
}

// ---------------------------------------------------------------------------
// Calling entry points
// ---------------------------------------------------------------------------

/// Outcome of one raw module call.
enum Raw {
    Status(Status, c_int),
    /// TRYAGAIN with ERANGE: retry with a larger scratch buffer.
    Range,
}

fn classify(status: c_int, errnop: c_int) -> Raw {
    let status = Status::from_raw(status);
    if status == Status::TryAgain && errnop == libc::ERANGE {
        Raw::Range
    } else {
        Raw::Status(status, errnop)
    }
}

/// Call `invoke(buf, len, &mut errno)` with a scratch buffer that doubles on
/// ERANGE, then `convert` the SUCCESS result while the buffer is alive.
fn with_scratch<T>(
    mut invoke: impl FnMut(*mut c_char, usize, &mut c_int) -> c_int,
    mut convert: impl FnMut() -> Option<T>,
) -> Answer<T> {
    let mut size = INITIAL_SCRATCH;
    loop {
        let mut scratch = vec![0u8; size];
        let mut err: c_int = 0;
        let rc = invoke(
            scratch.as_mut_ptr().cast::<c_char>(),
            scratch.len(),
            &mut err,
        );
        match classify(rc, err) {
            Raw::Range if size < MAX_SCRATCH => size *= 2,
            Raw::Range => return Answer::Unavailable(libc::ERANGE),
            Raw::Status(Status::Success, _) => {
                return match convert() {
                    Some(value) => Answer::Found(value),
                    None => Answer::Unavailable(libc::EINVAL),
                };
            }
            Raw::Status(Status::NotFound, _) => return Answer::NotFound,
            Raw::Status(Status::TryAgain, e) => return Answer::TryAgain(e),
            Raw::Status(Status::Unavailable, e) => return Answer::Unavailable(e),
        }
    }
}

/// Copy a module-provided C string (NULL reads as empty).
///
/// # Safety
/// `ptr` is NULL or a NUL-terminated string the module just returned.
unsafe fn owned(ptr: *const c_char) -> Vec<u8> {
    if ptr.is_null() {
        Vec::new()
    } else {
        // SAFETY: per the module ABI, result strings are NUL-terminated.
        unsafe { CStr::from_ptr(ptr) }.to_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// Stateful netgroup modules
// ---------------------------------------------------------------------------

/// A module's NULL field is a wildcard. A non-NULL empty string is a literal
/// empty value, so the files parser's empty-vector representation is not enough.
pub(crate) struct NetgroupTriple {
    pub host: Option<Vec<u8>>,
    pub user: Option<Vec<u8>>,
    pub domain: Option<Vec<u8>>,
    // GNU's files parser reserves three field terminators even for wildcards.
    // A module's NULL fields require no output bytes; non-NULL empty fields do.
    buffer_nuls: usize,
}

impl NetgroupTriple {
    pub(crate) fn required_buffer_size(&self) -> Option<usize> {
        [&self.host, &self.user, &self.domain]
            .into_iter()
            .try_fold(self.buffer_nuls, |size, field| {
                size.checked_add(field.as_ref().map_or(0, Vec::len))
            })
    }
}

enum NetgroupMember {
    Triple(NetgroupTriple),
    Group(Vec<u8>),
}

/// GNU's LP64 __netgrent module ABI, as declared by nss/netgroup.h.
/// The three callback declarations are provided by the installed <nss.h>.
/// The opaque pointers belong to the module; only its end callback frees them.
#[repr(C)]
struct NetgroupModuleState {
    kind: c_int,
    value: [*const c_char; 3],
    data: *mut c_char,
    data_size: usize,
    position: usize,
    first: c_int,
    known_groups: *mut c_void,
    needed_groups: *mut c_void,
    service: *mut c_void,
}

const _: () = {
    assert!(size_of::<NetgroupModuleState>() == 88);
    assert!(std::mem::offset_of!(NetgroupModuleState, value) == 8);
    assert!(std::mem::offset_of!(NetgroupModuleState, data) == 32);
    assert!(std::mem::offset_of!(NetgroupModuleState, position) == 48);
    assert!(std::mem::offset_of!(NetgroupModuleState, first) == 56);
    assert!(std::mem::offset_of!(NetgroupModuleState, service) == 80);
};

type SetNetgroupFn = unsafe extern "C" fn(*const c_char, *mut NetgroupModuleState) -> c_int;
type GetNetgroupFn =
    unsafe extern "C" fn(*mut NetgroupModuleState, *mut c_char, usize, *mut c_int) -> c_int;
type EndNetgroupFn = unsafe extern "C" fn(*mut NetgroupModuleState) -> c_int;

struct NetgroupModuleCursor {
    // Pin the callback state at one address from set through end, even when the
    // owning session moves into TLS or is temporarily leased out for a callback.
    state: Box<NetgroupModuleState>,
    get: GetNetgroupFn,
    end: EndNetgroupFn,
    scratch: Vec<u8>,
}

// SAFETY: GNU's reentrant netgroup module API stores per-enumeration state in
// the caller's __netgrent. This cursor uniquely owns that state and buffer;
// no callback can run concurrently, and no borrowed result escapes next().
unsafe impl Send for NetgroupModuleCursor {}

impl Drop for NetgroupModuleCursor {
    fn drop(&mut self) {
        // SAFETY: the matching end callback receives the same live state as
        // set/get. Cleanup must not overwrite the result's observable errno.
        unsafe {
            let error = libc::__errno_location();
            let saved = *error;
            (self.end)(&mut *self.state);
            *error = saved;
        }
    }
}

impl NetgroupModuleCursor {
    fn open(service: &[u8], group: &[u8]) -> (c_int, Option<Self>, c_int) {
        let Some(set) = module_function(service, "setnetgrent") else {
            return (-1, None, libc::ENOENT);
        };
        let Some(get) = module_function(service, "getnetgrent_r") else {
            return (-1, None, libc::ENOSYS);
        };
        let Some(end) = module_function(service, "endnetgrent") else {
            return (-1, None, libc::ENOSYS);
        };
        let Ok(group) = std::ffi::CString::new(group) else {
            return (-1, None, libc::EINVAL);
        };
        // SAFETY: symbols have the signatures in <nss.h>. All-zero pointer,
        // integer and union storage is the initial GNU module state.
        let (set, get, end, state) = unsafe {
            (
                core::mem::transmute::<usize, SetNetgroupFn>(set),
                core::mem::transmute::<usize, GetNetgroupFn>(get),
                core::mem::transmute::<usize, EndNetgroupFn>(end),
                Box::new(std::mem::zeroed::<NetgroupModuleState>()),
            )
        };
        let mut cursor = Self {
            state,
            get,
            end,
            scratch: vec![0; INITIAL_SCRATCH],
        };
        // setnetgrent has no errnop argument: preserve the caller's errno while
        // retaining any failure written by the module itself.
        let (status, error) = unsafe {
            let error = libc::__errno_location();
            let saved = *error;
            *error = 0;
            let status = set(group.as_ptr(), &mut *cursor.state);
            let result = *error;
            *error = saved;
            (status, result)
        };
        if status == 1 {
            (status, Some(cursor), error)
        } else {
            // Drop also runs after failed setup, allowing a module to release
            // a partial allocation. It never changes the captured failure.
            (status, None, error)
        }
    }

    fn resize_scratch(&mut self, capacity: usize) -> Result<(), c_int> {
        if capacity > self.scratch.len() {
            self.scratch
                .try_reserve_exact(capacity - self.scratch.len())
                .map_err(|_| libc::ENOMEM)?;
        }
        self.scratch.resize(capacity, 0);
        Ok(())
    }

    fn next(&mut self, capacity: usize) -> Result<Option<NetgroupMember>, c_int> {
        // Both enumeration and membership expose this budget to the module,
        // including for group references and private scratch. Growing here
        // would hide an observable ERANGE or incorrectly grant membership.
        self.resize_scratch(capacity)?;
        // GNU passes its errno slot directly. Preserve untouched errnop and
        // errors from NOTFOUND even when a pending child later yields a tuple.
        let error = unsafe { crate::errno_abi::__errno_location() };
        // SAFETY: state and scratch are unique writable module storage; error
        // names this thread's canonical errno cell. No Rust reference spans
        // the callback, which may itself call other libc functions.
        let status = unsafe {
            (self.get)(
                &mut *self.state,
                self.scratch.as_mut_ptr().cast(),
                self.scratch.len(),
                error,
            )
        };
        match status {
            1 => match self.state.kind {
                0 => {
                    // SAFETY: a successful NSS result supplies live
                    // NUL-terminated strings or NULL wildcards. Copy
                    // before another callback can invalidate them.
                    let field = |pointer: *const c_char| {
                        (!pointer.is_null()).then(|| unsafe { owned(pointer) })
                    };
                    Ok(Some(NetgroupMember::Triple(NetgroupTriple {
                        host: field(self.state.value[0]),
                        user: field(self.state.value[1]),
                        domain: field(self.state.value[2]),
                        buffer_nuls: self
                            .state
                            .value
                            .iter()
                            .filter(|pointer| !pointer.is_null())
                            .count(),
                    })))
                }
                1 if !self.state.value[0].is_null() => {
                    // SAFETY: kind=group supplies a live group name.
                    Ok(Some(NetgroupMember::Group(unsafe {
                        owned(self.state.value[0])
                    })))
                }
                _ => Err(libc::EINVAL),
            },
            // Both statuses finish this group and permit queued children.
            0 | 2 => Ok(None),
            -2 | -1 => Err(unsafe { *error }),
            _ => Err(libc::EINVAL),
        }
    }
}

enum NetgroupSource {
    Files {
        triples: std::vec::IntoIter<frankenlibc_core::netgroup::NetgroupTriple>,
        groups: std::vec::IntoIter<Vec<u8>>,
    },
    Module(NetgroupModuleCursor),
}

impl NetgroupSource {
    fn next(&mut self, capacity: usize) -> Result<Option<NetgroupMember>, c_int> {
        match self {
            Self::Module(cursor) => cursor.next(capacity),
            Self::Files { triples, groups } => {
                if let Some(triple) = triples.as_slice().first() {
                    let needed = [&triple.host, &triple.user, &triple.domain]
                        .into_iter()
                        .try_fold(3usize, |size, field| size.checked_add(field.len()));
                    if needed.is_none_or(|needed| needed > capacity) {
                        return Err(libc::ERANGE);
                    }
                }
                if let Some(triple) = triples.next() {
                    let field = |value: Vec<u8>| (!value.is_empty()).then_some(value);
                    Ok(Some(NetgroupMember::Triple(NetgroupTriple {
                        host: field(triple.host),
                        user: field(triple.user),
                        domain: field(triple.domain),
                        buffer_nuls: 3,
                    })))
                } else {
                    Ok(groups.next().map(NetgroupMember::Group))
                }
            }
        }
    }
}

/// One independent traversal. Source selection follows setnetgrent statuses;
/// read failures never authorize falling through to a different source.
/// Nested names share one configuration image and are expanded without Rust
/// recursion, so cycles cannot exhaust the stack.
pub(crate) struct NetgroupSession {
    services: Arc<Vec<Service>>,
    membership: bool,
    files: Option<Result<Vec<u8>, c_int>>,
    source: Option<NetgroupSource>,
    visited: std::collections::HashSet<Vec<u8>>,
    pending: Vec<Vec<u8>>,
}

impl NetgroupSession {
    pub(crate) fn open(group: &[u8], membership: bool) -> Result<Option<Self>, c_int> {
        let mut session = Self {
            services: services(Database::Netgroup),
            membership,
            files: None,
            source: None,
            visited: std::collections::HashSet::new(),
            pending: Vec::new(),
        };
        let Some(source) = session.select_source(group)? else {
            return Ok(None);
        };
        session.visited.insert(group.to_vec());
        session.source = Some(source);
        Ok(Some(session))
    }

    fn select_source(&mut self, group: &[u8]) -> Result<Option<NetgroupSource>, c_int> {
        use frankenlibc_core::nss::Action;

        for (index, service) in self.services.iter().enumerate() {
            let (raw_status, source, error) = if service.name() == b"files" {
                let content = self.files.get_or_insert_with(|| {
                    std::fs::read(crate::unistd_abi::NETGROUP_PATH)
                        .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
                });
                match content {
                    Ok(bytes) => match frankenlibc_core::netgroup::netgroup_record(bytes, group) {
                        Some(record) => (
                            1,
                            Some(NetgroupSource::Files {
                                triples: record.triples.into_iter(),
                                groups: record.groups.into_iter(),
                            }),
                            0,
                        ),
                        None => (0, None, 0),
                    },
                    Err(error) if matches!(*error, libc::ENOMEM | libc::EAGAIN) => {
                        (-2, None, *error)
                    }
                    Err(error) => (-1, None, *error),
                }
            } else {
                let (status, cursor, error) = NetgroupModuleCursor::open(service.name(), group);
                (status, cursor.map(NetgroupSource::Module), error)
            };
            // RETURN stops by default. Negated status clauses can change its
            // action independently of the four ordinary status actions.
            if raw_status == 2 {
                if service.return_action() != Action::Continue {
                    return Ok(None);
                }
                continue;
            }
            let status = Status::from_raw(raw_status);
            let stop = index + 1 == self.services.len()
                || service.action(status) != Action::Continue
                || (self.membership && status == Status::Success);
            if stop {
                return match source {
                    Some(source) => Ok(Some(source)),
                    None if error != 0 => Err(error),
                    None => Ok(None),
                };
            }
            // A SUCCESS=continue cursor is dropped here before opening the
            // next source. A module never shares another module's private data.
        }
        Ok(None)
    }

    /// GNU membership uses a fixed 1024-byte module buffer. A provider's
    /// ERANGE must deny this lookup, even when its final fields would fit.
    pub(crate) fn next(&mut self) -> Result<Option<NetgroupTriple>, c_int> {
        self.next_with_capacity(INITIAL_SCRATCH)
    }

    /// Public enumeration must preserve the caller's exact module buffer
    /// contract. An ERANGE leaves this cursor positioned for the next call.
    pub(crate) fn next_for_buffer(
        &mut self,
        capacity: usize,
    ) -> Result<Option<NetgroupTriple>, c_int> {
        self.next_with_capacity(capacity)
    }

    fn next_with_capacity(&mut self, capacity: usize) -> Result<Option<NetgroupTriple>, c_int> {
        loop {
            if let Some(source) = self.source.as_mut() {
                match source.next(capacity)? {
                    Some(NetgroupMember::Triple(triple)) => return Ok(Some(triple)),
                    Some(NetgroupMember::Group(group)) => {
                        // GNU suppresses references already awaiting lookup,
                        // not just groups already visited. Deduplicating only
                        // when popping would reorder A B A into A B.
                        if !self.visited.contains(&group) && !self.pending.contains(&group) {
                            self.pending.push(group);
                        }
                        continue;
                    }
                    None => self.source = None,
                }
            }
            let Some(group) = self.pending.pop() else {
                return Ok(None);
            };
            if !self.visited.insert(group.clone()) {
                continue;
            }
            self.source = self.select_source(&group)?;
        }
    }
}

/// The port variant retains the complete C int in network byte order.
/// Narrowing it before a module call would make invalid high bits alias a
/// valid service and would change a module's own matching contract.
#[derive(Clone, Copy)]
pub(crate) enum ServiceKey<'a> {
    Name(&'a [u8]),
    Port(c_int),
}

type ServiceNameFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *mut libc::servent,
    *mut c_char,
    usize,
    *mut c_int,
) -> c_int;
type ServicePortFn = unsafe extern "C" fn(
    c_int,
    *const c_char,
    *mut libc::servent,
    *mut c_char,
    usize,
    *mut c_int,
) -> c_int;

struct ServiceQuery<'a> {
    address: usize,
    key: ServiceKey<'a>,
    name: Vec<u8>,
    protocol: Option<Vec<u8>>,
}

impl<'a> ServiceQuery<'a> {
    fn new(service: &[u8], key: ServiceKey<'a>, protocol: Option<&[u8]>) -> Option<Self> {
        let function = match key {
            ServiceKey::Name(_) => "getservbyname_r",
            ServiceKey::Port(_) => "getservbyport_r",
        };
        let address = module_function(service, function)?;
        let terminated = |bytes: &[u8]| {
            let mut value = Vec::with_capacity(bytes.len() + 1);
            value.extend_from_slice(bytes);
            value.push(0);
            value
        };
        Some(Self {
            address,
            key,
            name: match key {
                ServiceKey::Name(name) => terminated(name),
                ServiceKey::Port(_) => Vec::new(),
            },
            protocol: protocol.map(terminated),
        })
    }

    /// # Safety
    /// `out`, `buf[..len]`, and `error` are writable for the NSS callback.
    unsafe fn call(
        &self,
        out: *mut libc::servent,
        buf: *mut c_char,
        len: usize,
        error: *mut c_int,
    ) -> c_int {
        let protocol = self
            .protocol
            .as_ref()
            .map_or(std::ptr::null(), |value| value.as_ptr().cast());
        match self.key {
            ServiceKey::Name(_) => {
                // SAFETY: this address was resolved with the by-name NSS ABI;
                // argument strings are terminated and the caller owns outputs.
                let call: ServiceNameFn = unsafe { core::mem::transmute(self.address) };
                unsafe { call(self.name.as_ptr().cast(), protocol, out, buf, len, error) }
            }
            ServiceKey::Port(port) => {
                // SAFETY: the by-port ABI takes an int, not a host-order u16.
                let call: ServicePortFn = unsafe { core::mem::transmute(self.address) };
                unsafe { call(port, protocol, out, buf, len, error) }
            }
        }
    }

    /// # Safety
    /// `out` and `buf[..len]` are writable for the installed NSS callback.
    unsafe fn answer(&self, out: *mut libc::servent, buf: *mut c_char, len: usize) -> Answer<()> {
        // GNU passes the calling thread's errno address to service modules.
        // A provider that leaves errnop untouched on failure preserves the
        // incoming errno; a successful lookup or definitive miss clears it.
        // Keep a raw pointer so reentrant callbacks do not alias a Rust borrow.
        let error = unsafe { crate::errno_abi::__errno_location() };
        let status = unsafe { self.call(out, buf, len, error) };
        match classify(status, unsafe { *error }) {
            Raw::Range => Answer::BufferTooSmall,
            Raw::Status(Status::Success, _) => {
                unsafe { *error = 0 };
                Answer::Found(())
            }
            Raw::Status(Status::NotFound, _) => {
                unsafe { *error = 0 };
                Answer::NotFound
            }
            Raw::Status(Status::TryAgain, error) => Answer::TryAgain(error),
            Raw::Status(Status::Unavailable, error) => Answer::Unavailable(error),
        }
    }
}

/// # Safety
/// A successful installed module supplies terminated strings and alias table
/// that remain readable until its caller buffer is released.
unsafe fn service_from_c(entry: &libc::servent) -> Option<frankenlibc_core::resolv::ServiceEntry> {
    if entry.s_name.is_null() || entry.s_proto.is_null() {
        return None;
    }
    let mut aliases = Vec::new();
    if !entry.s_aliases.is_null() {
        for index in 0..MAX_SCRATCH / size_of::<usize>() {
            // SAFETY: the successful module result supplies a terminated table.
            let alias = unsafe { *entry.s_aliases.add(index) };
            if alias.is_null() {
                break;
            }
            // SAFETY: each non-null table entry is a terminated string.
            aliases.push(unsafe { owned(alias) });
            if index + 1 == MAX_SCRATCH / size_of::<usize>() {
                return None;
            }
        }
    }
    Some(frankenlibc_core::resolv::ServiceEntry {
        // SAFETY: name/protocol satisfy the successful module result contract.
        name: unsafe { owned(entry.s_name) },
        protocol: unsafe { owned(entry.s_proto) },
        port: u16::from_be(entry.s_port as u16),
        aliases,
    })
}

/// Own every result field before growing/releasing the module scratch buffer.
pub(crate) fn service_entry(
    service: &[u8],
    key: ServiceKey<'_>,
    protocol: Option<&[u8]>,
) -> Answer<frankenlibc_core::resolv::ServiceEntry> {
    let Some(query) = ServiceQuery::new(service, key, protocol) else {
        return Answer::Unavailable(missing_source());
    };
    let mut out = MaybeUninit::<libc::servent>::zeroed();
    let out = out.as_mut_ptr();
    let mut size = INITIAL_SCRATCH;
    loop {
        let mut scratch = vec![0u8; size];
        // SAFETY: out and this iteration's scratch buffer are live.
        match unsafe { query.answer(out, scratch.as_mut_ptr().cast(), scratch.len()) } {
            Answer::BufferTooSmall if size < MAX_SCRATCH => size *= 2,
            Answer::Found(()) => {
                // SAFETY: copy every field before this scratch buffer drops.
                return unsafe { service_from_c(&*out) }
                    .map_or(Answer::Unavailable(libc::EINVAL), Answer::Found);
            }
            Answer::NotFound => return Answer::NotFound,
            Answer::Unavailable(error) => return Answer::Unavailable(error),
            Answer::TryAgain(error) => return Answer::TryAgain(error),
            // An exhausted scratch budget is still ERANGE, not UNAVAIL:
            // source actions must not turn it into a later source's answer.
            Answer::BufferTooSmall => return Answer::BufferTooSmall,
        }
    }
}

/// The reentrant APIs pass the actual caller buffer to the module. In
/// particular, ERANGE must stop source traversal even when TRYAGAIN=continue;
/// silently growing an internal buffer would execute later sources wrongly.
///
/// # Safety
/// `out` is writable and `buf` covers `len` writable bytes for the callback.
pub(crate) unsafe fn service_entry_r(
    service: &[u8],
    key: ServiceKey<'_>,
    protocol: Option<&[u8]>,
    out: *mut libc::servent,
    buf: *mut c_char,
    len: usize,
) -> Answer<()> {
    let Some(query) = ServiceQuery::new(service, key, protocol) else {
        return Answer::Unavailable(missing_source());
    };
    // SAFETY: the caller validated its result and buffer before dispatch.
    unsafe { query.answer(out, buf, len) }
}

/// Every pointer returned by a hosts module is copied before its scratch
/// buffer is released. The canonical-name extension is distinct from h_name.
pub(crate) struct HostEntry {
    pub name: Vec<u8>,
    pub canonical_name: Option<Vec<u8>>,
    pub aliases: Vec<Vec<u8>>,
    pub addresses: Vec<std::net::IpAddr>,
}

/// The getaddrinfo module ABI can return both families in one list and attach
/// an interface scope to each IPv6 address. A hostent cannot represent these.
pub(crate) struct AddrInfoEntry {
    pub canonical_name: Option<Vec<u8>>,
    pub addresses: Vec<(std::net::IpAddr, u32)>,
}

/// Public <nss.h> layout for gethostbyname4_r.
#[repr(C)]
struct GaihAddrTuple {
    next: *mut GaihAddrTuple,
    name: *mut c_char,
    family: c_int,
    address: [u32; 4],
    scope_id: u32,
}

type HostAnswer = frankenlibc_core::addrinfo::hosts_policy::BackendResult<HostEntry, c_int>;

/// # Safety
/// The installed NSS module returned SUCCESS and its hostent fields follow
/// the public NSS ABI, including NUL-terminated string and pointer arrays.
unsafe fn host_from_c(host: &libc::hostent, family: c_int) -> Option<HostEntry> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let width = match family {
        libc::AF_INET => 4,
        libc::AF_INET6 => 16,
        _ => return None,
    };
    if host.h_addrtype != family
        || host.h_length != width
        || host.h_name.is_null()
        || host.h_addr_list.is_null()
    {
        return None;
    }
    let mut aliases = Vec::new();
    if !host.h_aliases.is_null() {
        for index in 0..MAX_SCRATCH / size_of::<usize>() {
            // SAFETY: the module's successful result supplies a terminated table.
            let alias = unsafe { *host.h_aliases.add(index) };
            if alias.is_null() {
                break;
            }
            aliases.push(unsafe { owned(alias) });
            if index + 1 == MAX_SCRATCH / size_of::<usize>() {
                return None;
            }
        }
    }
    let mut addresses = Vec::new();
    for index in 0..MAX_SCRATCH / size_of::<usize>() {
        // SAFETY: each address has h_length bytes; byte arrays need no alignment.
        let address = unsafe { *host.h_addr_list.add(index) };
        if address.is_null() {
            break;
        }
        addresses.push(if family == libc::AF_INET {
            IpAddr::V4(Ipv4Addr::from(unsafe { *address.cast::<[u8; 4]>() }))
        } else {
            IpAddr::V6(Ipv6Addr::from(unsafe { *address.cast::<[u8; 16]>() }))
        });
        if index + 1 == MAX_SCRATCH / size_of::<usize>() {
            return None;
        }
    }
    if addresses.is_empty() {
        return None;
    }
    Some(HostEntry {
        name: unsafe { owned(host.h_name) },
        canonical_name: None,
        aliases,
        addresses,
    })
}

fn host_answer<T>(
    answer: Answer<T>,
    host_error: c_int,
) -> frankenlibc_core::addrinfo::hosts_policy::BackendResult<T, c_int> {
    use frankenlibc_core::addrinfo::hosts_policy::BackendResult;
    match answer {
        Answer::Found(entry) => BackendResult::Success(entry),
        Answer::NotFound => BackendResult::NotFound(if host_error == 4 {
            libc::EAI_NODATA
        } else {
            libc::EAI_NONAME
        }),
        Answer::TryAgain(_) => BackendResult::TryAgain(libc::EAI_AGAIN),
        Answer::Unavailable(_) | Answer::BufferTooSmall => {
            BackendResult::Unavailable(libc::EAI_FAIL)
        }
    }
}

/// Try the combined-family entry point used for AF_UNSPEC getaddrinfo.
/// None means the module has no such symbol. A negative answer must reach the
/// NSS status policy without falling back to another operation in that module.
pub(crate) fn gethostbyname4(
    service: &[u8],
    name: &[u8],
) -> Option<frankenlibc_core::addrinfo::hosts_policy::BackendResult<AddrInfoEntry, c_int>> {
    use frankenlibc_core::addrinfo::hosts_policy::BackendResult;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if name.contains(&0) {
        return Some(BackendResult::Unavailable(libc::EAI_FAIL));
    }
    let address = module_function(service, "gethostbyname4_r")?;
    type Name4 = unsafe extern "C" fn(
        *const c_char,
        *mut *mut GaihAddrTuple,
        *mut c_char,
        usize,
        *mut c_int,
        *mut c_int,
        *mut i32,
    ) -> c_int;
    // SAFETY: the loaded symbol implements the public NSS tuple prototype.
    let function: Name4 = unsafe { core::mem::transmute(address) };
    let mut key = name.to_vec();
    key.push(0);
    let first = std::cell::Cell::new(std::ptr::null_mut::<GaihAddrTuple>());
    let host_error = std::cell::Cell::new(0);
    let result = with_scratch(
        |buf, len, errno| {
            // An ERANGE attempt may have published a partial list into its
            // old scratch allocation. Start every retry with a fresh output.
            let mut head = std::ptr::null_mut();
            let mut h_errno = 0;
            let mut ttl = 0;
            // SAFETY: all output slots and the supplied scratch buffer remain
            // writable for this call; the input name is NUL-terminated.
            let status = unsafe {
                function(
                    key.as_ptr().cast(),
                    &mut head,
                    buf,
                    len,
                    errno,
                    &mut h_errno,
                    &mut ttl,
                )
            };
            first.set(head);
            host_error.set(h_errno);
            status
        },
        || {
            let mut current = first.get();
            if current.is_null() {
                return None;
            }
            // SAFETY: SUCCESS supplies a valid first tuple and an optional
            // NUL-terminated name; conversion precedes scratch deallocation.
            let canonical_name =
                unsafe { (!(*current).name.is_null()).then(|| owned((*current).name)) };
            let mut addresses = Vec::new();
            let mut visited = std::collections::HashSet::new();
            while !current.is_null() {
                if addresses.len() >= MAX_SCRATCH / size_of::<GaihAddrTuple>()
                    || !visited.insert(current as usize)
                {
                    return None;
                }
                // SAFETY: the module's successful list follows the public ABI.
                // The traversal bound and visited set reject cyclic results.
                let tuple = unsafe { &*current };
                let (address, scope_id) = match tuple.family {
                    libc::AF_INET => (
                        IpAddr::V4(Ipv4Addr::from(tuple.address[0].to_ne_bytes())),
                        0,
                    ),
                    libc::AF_INET6 => {
                        let mut bytes = [0u8; 16];
                        for (target, word) in
                            bytes.as_chunks_mut::<4>().0.iter_mut().zip(tuple.address)
                        {
                            target.copy_from_slice(&word.to_ne_bytes());
                        }
                        (IpAddr::V6(Ipv6Addr::from(bytes)), tuple.scope_id)
                    }
                    _ => return None,
                };
                addresses.push((address, scope_id));
                current = tuple.next;
            }
            Some(AddrInfoEntry {
                canonical_name,
                addresses,
            })
        },
    );
    Some(host_answer(result, host_error.get()))
}

/// Query the newest available hosts entry point. Falling back is only for an
/// absent symbol, never for a negative answer from an implemented operation.
pub(crate) fn gethostbyname(service: &[u8], name: &[u8], family: c_int) -> HostAnswer {
    use frankenlibc_core::addrinfo::hosts_policy::BackendResult;
    if !matches!(family, libc::AF_INET | libc::AF_INET6) || name.contains(&0) {
        return BackendResult::Unavailable(libc::EAI_FAIL);
    }
    let selected = module_function(service, "gethostbyname3_r")
        .map(|address| (address, 3))
        .or_else(|| module_function(service, "gethostbyname2_r").map(|address| (address, 2)))
        .or_else(|| {
            (family == libc::AF_INET)
                .then(|| module_function(service, "gethostbyname_r"))
                .flatten()
                .map(|address| (address, 1))
        });
    let Some((address, version)) = selected else {
        return BackendResult::Unavailable(libc::EAI_NONAME);
    };
    type Name3 = unsafe extern "C" fn(
        *const c_char,
        c_int,
        *mut libc::hostent,
        *mut c_char,
        usize,
        *mut c_int,
        *mut c_int,
        *mut i32,
        *mut *mut c_char,
    ) -> c_int;
    type Name2 = unsafe extern "C" fn(
        *const c_char,
        c_int,
        *mut libc::hostent,
        *mut c_char,
        usize,
        *mut c_int,
        *mut c_int,
    ) -> c_int;
    type Name1 = unsafe extern "C" fn(
        *const c_char,
        *mut libc::hostent,
        *mut c_char,
        usize,
        *mut c_int,
        *mut c_int,
    ) -> c_int;
    let mut key = name.to_vec();
    key.push(0);
    let mut out = MaybeUninit::<libc::hostent>::zeroed();
    let out = out.as_mut_ptr();
    let host_error = std::cell::Cell::new(0);
    let canonical = std::cell::Cell::new(std::ptr::null_mut::<c_char>());
    let result = with_scratch(
        |buf, len, errno| {
            let mut h_errno = 0;
            let mut ttl = 0;
            let mut canon = std::ptr::null_mut();
            // SAFETY: selected symbol has the documented versioned NSS ABI;
            // key and every output buffer remain alive throughout the call.
            let status = unsafe {
                match version {
                    3 => {
                        let f: Name3 = core::mem::transmute(address);
                        f(
                            key.as_ptr().cast(),
                            family,
                            out,
                            buf,
                            len,
                            errno,
                            &mut h_errno,
                            &mut ttl,
                            &mut canon,
                        )
                    }
                    2 => {
                        let f: Name2 = core::mem::transmute(address);
                        f(
                            key.as_ptr().cast(),
                            family,
                            out,
                            buf,
                            len,
                            errno,
                            &mut h_errno,
                        )
                    }
                    _ => {
                        let f: Name1 = core::mem::transmute(address);
                        f(key.as_ptr().cast(), out, buf, len, errno, &mut h_errno)
                    }
                }
            };
            host_error.set(h_errno);
            canonical.set(canon);
            status
        },
        || {
            // SAFETY: conversion runs only after SUCCESS, before scratch drops.
            let mut entry = unsafe { host_from_c(&*out, family) }?;
            if !canonical.get().is_null() {
                entry.canonical_name = Some(unsafe { owned(canonical.get()) });
            }
            Some(entry)
        },
    );
    host_answer(result, host_error.get())
}

pub(crate) fn gethostbyaddr(service: &[u8], address: std::net::IpAddr) -> HostAnswer {
    use frankenlibc_core::addrinfo::hosts_policy::BackendResult;
    let selected = module_function(service, "gethostbyaddr2_r")
        .map(|address| (address, true))
        .or_else(|| module_function(service, "gethostbyaddr_r").map(|address| (address, false)));
    let Some((function, extended)) = selected else {
        return BackendResult::Unavailable(libc::EAI_NONAME);
    };
    type Addr2 = unsafe extern "C" fn(
        *const c_void,
        libc::socklen_t,
        c_int,
        *mut libc::hostent,
        *mut c_char,
        usize,
        *mut c_int,
        *mut c_int,
        *mut i32,
    ) -> c_int;
    type Addr1 = unsafe extern "C" fn(
        *const c_void,
        libc::socklen_t,
        c_int,
        *mut libc::hostent,
        *mut c_char,
        usize,
        *mut c_int,
        *mut c_int,
    ) -> c_int;
    let (family, bytes) = match address {
        std::net::IpAddr::V4(ip) => (libc::AF_INET, ip.octets().to_vec()),
        std::net::IpAddr::V6(ip) => (libc::AF_INET6, ip.octets().to_vec()),
    };
    let mut out = MaybeUninit::<libc::hostent>::zeroed();
    let out = out.as_mut_ptr();
    let host_error = std::cell::Cell::new(0);
    let result = with_scratch(
        |buf, len, errno| {
            let mut h_errno = 0;
            let mut ttl = 0;
            // SAFETY: the module's version selects the exact NSS prototype.
            let status = unsafe {
                if extended {
                    let f: Addr2 = core::mem::transmute(function);
                    f(
                        bytes.as_ptr().cast(),
                        bytes.len() as libc::socklen_t,
                        family,
                        out,
                        buf,
                        len,
                        errno,
                        &mut h_errno,
                        &mut ttl,
                    )
                } else {
                    let f: Addr1 = core::mem::transmute(function);
                    f(
                        bytes.as_ptr().cast(),
                        bytes.len() as libc::socklen_t,
                        family,
                        out,
                        buf,
                        len,
                        errno,
                        &mut h_errno,
                    )
                }
            };
            host_error.set(h_errno);
            status
        },
        // SAFETY: conversion runs only after SUCCESS, before scratch drops.
        || unsafe { host_from_c(&*out, family) },
    );
    host_answer(result, host_error.get())
}

/// # Safety
/// `pw` was filled by a module call that reported SUCCESS.
unsafe fn passwd_from_c(pw: &libc::passwd) -> frankenlibc_core::pwd::Passwd {
    // SAFETY: SUCCESS means every string field is NULL or a valid C string.
    unsafe {
        frankenlibc_core::pwd::Passwd {
            pw_name: owned(pw.pw_name),
            pw_passwd: owned(pw.pw_passwd),
            pw_uid: pw.pw_uid,
            pw_gid: pw.pw_gid,
            pw_gecos: owned(pw.pw_gecos),
            pw_dir: owned(pw.pw_dir),
            pw_shell: owned(pw.pw_shell),
            nis_compat_null_fields: false,
        }
    }
}

/// # Safety
/// `gr` was filled by a module call that reported SUCCESS.
unsafe fn group_from_c(gr: &libc::group) -> frankenlibc_core::grp::Group {
    let mut members = Vec::new();
    if !gr.gr_mem.is_null() {
        let mut index = 0usize;
        loop {
            // SAFETY: gr_mem is a NULL-terminated array of C strings.
            let member = unsafe { *gr.gr_mem.add(index) };
            if member.is_null() {
                break;
            }
            // SAFETY: each entry is a valid C string.
            members.push(unsafe { owned(member) });
            index += 1;
        }
    }
    frankenlibc_core::grp::Group {
        // SAFETY: SUCCESS means the string fields are NULL or valid C strings.
        gr_name: unsafe { owned(gr.gr_name) },
        gr_passwd: unsafe { owned(gr.gr_passwd) },
        gr_gid: gr.gr_gid,
        gr_mem: members,
        nis_compat_null_fields: false,
    }
}

/// # Safety
/// `sp` was filled by a module call that reported SUCCESS.
unsafe fn shadow_from_c(sp: &libc::spwd) -> frankenlibc_core::pwd::shadow::ShadowEntry {
    frankenlibc_core::pwd::shadow::ShadowEntry {
        // SAFETY: SUCCESS means the string fields are NULL or valid C strings.
        name: unsafe { owned(sp.sp_namp) },
        passwd: unsafe { owned(sp.sp_pwdp) },
        lstchg: sp.sp_lstchg,
        min: sp.sp_min,
        max: sp.sp_max,
        warn: sp.sp_warn,
        inact: sp.sp_inact,
        expire: sp.sp_expire,
        flag: sp.sp_flag,
    }
}

/// The errno a missing module or entry point reports: glibc leaves errno
/// untouched for a source it could not load, and the `_r` functions return
/// whatever errno then holds.
fn missing_source() -> c_int {
    // SAFETY: __errno_location returns this thread's errno slot.
    unsafe { *crate::errno_abi::__errno_location() }
}

/// Secure RPC modules have fixed-output entry points rather than the account
/// databases' resizable `_r` ABI. Keep their outputs private until SUCCESS so
/// a failed or malformed answer cannot publish a partial local identity.
pub(crate) fn netname2user(
    service: &[u8],
    netname: &[u8],
) -> Answer<frankenlibc_core::rpc::NetidUser> {
    use frankenlibc_core::rpc::{NETID_MAX_GROUPS, NetidUser};
    type Function = unsafe extern "C" fn(
        *mut c_char,
        *mut libc::uid_t,
        *mut libc::gid_t,
        *mut c_int,
        *mut libc::gid_t,
        *mut c_int,
    ) -> c_int;
    let Some(address) = module_function(service, "netname2user") else {
        return Answer::Unavailable(missing_source());
    };
    let mut key = netname.to_vec();
    key.push(0);
    let mut groups = Vec::<libc::gid_t>::new();
    if groups.try_reserve_exact(NETID_MAX_GROUPS).is_err() {
        return Answer::TryAgain(libc::ENOMEM);
    }
    groups.resize(NETID_MAX_GROUPS, 0);
    let mut uid = 0;
    let mut gid = 0;
    let mut count = 0;
    // SAFETY: this is the six-argument nss_netname2user signature declared in
    // GNU <nss.h>. Older modules may ignore the final errno argument.
    let function: Function = unsafe { core::mem::transmute(address) };
    // SAFETY: the thread's errno slot is writable for the duration of the call.
    let error = unsafe { crate::errno_abi::__errno_location() };
    // SAFETY: key is a mutable C string; all scalar outputs and the public
    // NGROUPS-sized group array are owned, aligned and live across the call.
    let status = unsafe {
        function(
            key.as_mut_ptr().cast(),
            &mut uid,
            &mut gid,
            &mut count,
            groups.as_mut_ptr(),
            error,
        )
    };
    // SAFETY: error is this thread's valid errno pointer.
    let error = unsafe { *error };
    match Status::from_raw(status) {
        Status::Success if count >= 0 && count as usize <= NETID_MAX_GROUPS => {
            groups.truncate(count as usize);
            Answer::Found(NetidUser { uid, gid, groups })
        }
        Status::Success => Answer::Unavailable(libc::EINVAL),
        Status::NotFound => Answer::NotFound,
        Status::Unavailable => Answer::Unavailable(error),
        Status::TryAgain => Answer::TryAgain(error),
    }
}

/// Call the public `nss_getpublickey(const char *, char *, int *)` ABI.
pub(crate) fn getpublickey(
    service: &[u8],
    netname: &[u8],
) -> Answer<[u8; frankenlibc_core::rpc::PUBLICKEY_HEX_BYTES]> {
    use frankenlibc_core::rpc::PUBLICKEY_HEX_BYTES;
    type Function = unsafe extern "C" fn(*const c_char, *mut c_char, *mut c_int) -> c_int;
    let Some(address) = module_function(service, "getpublickey") else {
        return Answer::Unavailable(missing_source());
    };
    let mut key = netname.to_vec();
    key.push(0);
    let mut output = [0xffu8; PUBLICKEY_HEX_BYTES + 1];
    // SAFETY: the loaded entry point has the public nss_getpublickey signature.
    let function: Function = unsafe { core::mem::transmute(address) };
    // SAFETY: the thread's errno slot is valid throughout the module call.
    let error = unsafe { crate::errno_abi::__errno_location() };
    // SAFETY: key is a C string and the output holds a full HEXKEYBYTES key
    // plus NUL, as required by the public Secure RPC module ABI.
    let status = unsafe { function(key.as_ptr().cast(), output.as_mut_ptr().cast(), error) };
    // SAFETY: error is this thread's valid errno pointer.
    let error = unsafe { *error };
    match Status::from_raw(status) {
        Status::Success
            if output[PUBLICKEY_HEX_BYTES] == 0
                && output[..PUBLICKEY_HEX_BYTES]
                    .iter()
                    .all(u8::is_ascii_hexdigit) =>
        {
            let mut public = [0; PUBLICKEY_HEX_BYTES];
            public.copy_from_slice(&output[..PUBLICKEY_HEX_BYTES]);
            Answer::Found(public)
        }
        Status::Success => Answer::Unavailable(libc::EINVAL),
        Status::NotFound => Answer::NotFound,
        Status::Unavailable => Answer::Unavailable(error),
        Status::TryAgain => Answer::TryAgain(error),
    }
}

/// Call GNU's four-argument `nss_getsecretkey` ABI. An empty successful
/// result means that the password failed; it must retain NSS SUCCESS status.
pub(crate) fn getsecretkey(
    service: &[u8],
    netname: &[u8],
    password: &[u8],
) -> Answer<frankenlibc_core::rpc::secret::SecretKey> {
    use frankenlibc_core::rpc::{PUBLICKEY_HEX_BYTES, secret::SecretKey};
    type Function =
        unsafe extern "C" fn(*const c_char, *mut c_char, *mut c_char, *mut c_int) -> c_int;
    let Some(address) = module_function(service, "getsecretkey") else {
        return Answer::Unavailable(missing_source());
    };
    let mut name = Vec::new();
    let mut passwd = Vec::new();
    if name.try_reserve_exact(netname.len() + 1).is_err()
        || passwd.try_reserve_exact(password.len() + 1).is_err()
    {
        return Answer::TryAgain(libc::ENOMEM);
    }
    name.extend_from_slice(netname);
    name.push(0);
    passwd.extend_from_slice(password);
    passwd.push(0);
    let mut output = [0xffu8; PUBLICKEY_HEX_BYTES + 1];
    // SAFETY: GNU <nss.h> declares name, output, mutable password, errno in
    // this order. Both strings and the complete fixed-size output are private.
    let function: Function = unsafe { core::mem::transmute(address) };
    // SAFETY: the calling thread owns this writable errno slot.
    let error = unsafe { crate::errno_abi::__errno_location() };
    // SAFETY: all arguments stay live through the call. The full password is
    // passed to modules; only the native files DES backend truncates to eight.
    let status = unsafe {
        function(
            name.as_ptr().cast(),
            output.as_mut_ptr().cast(),
            passwd.as_mut_ptr().cast(),
            error,
        )
    };
    // SAFETY: error remains this thread's valid errno pointer.
    let error = unsafe { *error };
    match Status::from_raw(status) {
        Status::Success if output[0] == 0 => Answer::Found(SecretKey::WrongPassword),
        Status::Success
            if output[PUBLICKEY_HEX_BYTES] == 0
                && output[..PUBLICKEY_HEX_BYTES]
                    .iter()
                    .all(u8::is_ascii_hexdigit) =>
        {
            let mut secret = [0; PUBLICKEY_HEX_BYTES];
            secret.copy_from_slice(&output[..PUBLICKEY_HEX_BYTES]);
            Answer::Found(SecretKey::Key(secret))
        }
        Status::Success => Answer::Unavailable(libc::EINVAL),
        Status::NotFound => Answer::NotFound,
        Status::Unavailable => Answer::Unavailable(error),
        Status::TryAgain => Answer::TryAgain(error),
    }
}

type ByNameFn<T> =
    unsafe extern "C" fn(*const c_char, *mut T, *mut c_char, usize, *mut c_int) -> c_int;
type ByIdFn<T> = unsafe extern "C" fn(u32, *mut T, *mut c_char, usize, *mut c_int) -> c_int;
type GetEntFn<T> = unsafe extern "C" fn(*mut T, *mut c_char, usize, *mut c_int) -> c_int;
type SetEntFn = unsafe extern "C" fn(c_int) -> c_int;
type EndEntFn = unsafe extern "C" fn() -> c_int;

fn call_by_name<T, R>(
    service: &[u8],
    function: &'static str,
    key: &[u8],
    convert: unsafe fn(&T) -> R,
) -> Answer<R> {
    let Some(addr) = module_function(service, function) else {
        return Answer::Unavailable(missing_source());
    };
    let mut key_c = key.to_vec();
    key_c.push(0);
    // SAFETY: the entry point has the documented reentrant by-name signature.
    let f: ByNameFn<T> = unsafe { core::mem::transmute(addr) };
    let mut out = MaybeUninit::<T>::zeroed();
    let out = out.as_mut_ptr();
    with_scratch(
        // SAFETY: key_c is NUL-terminated; out/buf/err are valid for the call.
        |buf, len, err| unsafe { f(key_c.as_ptr().cast(), out, buf, len, err) },
        // SAFETY: called only after SUCCESS, while the scratch buffer is alive.
        || Some(unsafe { convert(&*out) }),
    )
}

fn call_by_id<T, R>(
    service: &[u8],
    function: &'static str,
    id: u32,
    convert: unsafe fn(&T) -> R,
) -> Answer<R> {
    let Some(addr) = module_function(service, function) else {
        return Answer::Unavailable(missing_source());
    };
    // SAFETY: the entry point has the documented reentrant by-id signature.
    let f: ByIdFn<T> = unsafe { core::mem::transmute(addr) };
    let mut out = MaybeUninit::<T>::zeroed();
    let out = out.as_mut_ptr();
    with_scratch(
        // SAFETY: out/buf/err are valid for the call.
        |buf, len, err| unsafe { f(id, out, buf, len, err) },
        // SAFETY: called only after SUCCESS, while the scratch buffer is alive.
        || Some(unsafe { convert(&*out) }),
    )
}

fn call_getent<T, R>(
    service: &[u8],
    function: &'static str,
    convert: unsafe fn(&T) -> R,
) -> Answer<R> {
    let Some(addr) = module_function(service, function) else {
        return Answer::Unavailable(missing_source());
    };
    // SAFETY: the entry point has the documented reentrant getent signature.
    let f: GetEntFn<T> = unsafe { core::mem::transmute(addr) };
    let mut out = MaybeUninit::<T>::zeroed();
    let out = out.as_mut_ptr();
    with_scratch(
        // SAFETY: out/buf/err are valid for the call.
        |buf, len, err| unsafe { f(out, buf, len, err) },
        // SAFETY: called only after SUCCESS, while the scratch buffer is alive.
        || Some(unsafe { convert(&*out) }),
    )
}

/// Call `_nss_<service>_set<db>ent(0)`. A missing module or entry point is an
/// unavailable source.
fn call_setent(service: &[u8], function: &'static str) -> Status {
    let Some(addr) = module_function(service, function) else {
        return Status::Unavailable;
    };
    // SAFETY: setXXent takes the stayopen flag and returns an nss_status.
    let f: SetEntFn = unsafe { core::mem::transmute(addr) };
    // SAFETY: plain call with an int argument.
    Status::from_raw(unsafe { f(0) })
}

fn call_endent(service: &[u8], function: &'static str) {
    if !module_loaded(service) {
        return;
    }
    if let Some(addr) = module_function(service, function) {
        // SAFETY: endXXent takes no arguments and returns an nss_status.
        let f: EndEntFn = unsafe { core::mem::transmute(addr) };
        // SAFETY: plain call.
        let _ = unsafe { f() };
    }
}

pub(crate) fn getpwnam(service: &[u8], name: &[u8]) -> Answer<frankenlibc_core::pwd::Passwd> {
    call_by_name::<libc::passwd, _>(service, "getpwnam_r", name, passwd_from_c)
}

pub(crate) fn getpwuid(service: &[u8], uid: u32) -> Answer<frankenlibc_core::pwd::Passwd> {
    call_by_id::<libc::passwd, _>(service, "getpwuid_r", uid, passwd_from_c)
}

pub(crate) fn getgrnam(service: &[u8], name: &[u8]) -> Answer<frankenlibc_core::grp::Group> {
    call_by_name::<libc::group, _>(service, "getgrnam_r", name, group_from_c)
}

pub(crate) fn getgrgid(service: &[u8], gid: u32) -> Answer<frankenlibc_core::grp::Group> {
    call_by_id::<libc::group, _>(service, "getgrgid_r", gid, group_from_c)
}

pub(crate) fn getspnam(
    service: &[u8],
    name: &[u8],
) -> Answer<frankenlibc_core::pwd::shadow::ShadowEntry> {
    call_by_name::<libc::spwd, _>(service, "getspnam_r", name, shadow_from_c)
}

/// The group merge rule measured on glibc: same name and gid, members
/// appended without de-duplication, the held entry's other fields kept.
pub(crate) fn merge_group(
    held: &mut frankenlibc_core::grp::Group,
    next: frankenlibc_core::grp::Group,
) -> bool {
    if held.gr_name != next.gr_name || held.gr_gid != next.gr_gid {
        return false;
    }
    held.gr_mem.extend(next.gr_mem);
    true
}

// ---------------------------------------------------------------------------
// Enumeration across sources
// ---------------------------------------------------------------------------

/// Which enumeration a cursor walks.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntDb {
    Passwd,
    Group,
    Shadow,
}

impl EntDb {
    fn database(self) -> Database {
        match self {
            Self::Passwd => Database::Passwd,
            Self::Group => Database::Group,
            Self::Shadow => Database::Shadow,
        }
    }
    fn set_fn(self) -> &'static str {
        match self {
            Self::Passwd => "setpwent",
            Self::Group => "setgrent",
            Self::Shadow => "setspent",
        }
    }
    fn end_fn(self) -> &'static str {
        match self {
            Self::Passwd => "endpwent",
            Self::Group => "endgrent",
            Self::Shadow => "endspent",
        }
    }
}

/// Position of a multi-source enumeration: the source being walked and
/// whether its `set*ent` has run (or, for files, its snapshot was taken).
#[derive(Clone, Copy, Default)]
pub(crate) struct EntCursor {
    pub(crate) source: usize,
    pub(crate) started: bool,
}

/// One step of `get*ent` from the source the cursor points at.
pub(crate) enum EntStep<T> {
    /// The cursor's source is the native files backend: the caller produces
    /// the next files entry (restarting its snapshot when `restart`).
    Files {
        restart: bool,
    },
    Module(Answer<T>),
    /// Enumeration is over.
    Done,
}

/// Decide what the cursor's current source should do next.
pub(crate) fn ent_step<T>(
    db: EntDb,
    cursor: &mut EntCursor,
    getent: impl FnOnce(&[u8]) -> Answer<T>,
) -> (EntStep<T>, Option<Service>) {
    let services = services(db.database());
    let Some(service) = services.get(cursor.source).cloned() else {
        return (EntStep::Done, None);
    };
    let restart = !cursor.started;
    cursor.started = true;
    match service.kind() {
        SourceKind::Files => (EntStep::Files { restart }, Some(service)),
        SourceKind::Module => {
            if restart {
                let status = call_setent(service.name(), db.set_fn());
                if status != Status::Success {
                    return (
                        EntStep::Module(match status {
                            Status::TryAgain => Answer::TryAgain(libc::EAGAIN),
                            _ => Answer::Unavailable(missing_source()),
                        }),
                        Some(service),
                    );
                }
            }
            (EntStep::Module(getent(service.name())), Some(service))
        }
    }
}

/// After the current source answered `status`: move to the next source
/// (returning true) or stop.
pub(crate) fn ent_advance(cursor: &mut EntCursor, service: &Service, status: Status) -> bool {
    if frankenlibc_core::nss::enumeration_advances(service, status) {
        cursor.source += 1;
        cursor.started = false;
        true
    } else {
        false
    }
}

/// `end*ent`: close every module source this process has loaded for `db`.
pub(crate) fn ent_end(db: EntDb) {
    for service in services(db.database()).iter() {
        if service.kind() == SourceKind::Module {
            call_endent(service.name(), db.end_fn());
        }
    }
}

pub(crate) fn getpwent(service: &[u8]) -> Answer<frankenlibc_core::pwd::Passwd> {
    call_getent::<libc::passwd, _>(service, "getpwent_r", passwd_from_c)
}

pub(crate) fn getgrent(service: &[u8]) -> Answer<frankenlibc_core::grp::Group> {
    call_getent::<libc::group, _>(service, "getgrent_r", group_from_c)
}

pub(crate) fn getspent(service: &[u8]) -> Answer<frankenlibc_core::pwd::shadow::ShadowEntry> {
    call_getent::<libc::spwd, _>(service, "getspent_r", shadow_from_c)
}

// ---------------------------------------------------------------------------
// initgroups
// ---------------------------------------------------------------------------

type InitgroupsDynFn = unsafe extern "C" fn(
    *const c_char,
    u32,
    *mut c_long,
    *mut c_long,
    *mut *mut u32,
    c_long,
    *mut c_int,
) -> c_int;

type MallocFn = unsafe extern "C" fn(usize) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);

/// The allocator a module's `realloc` of the group array binds to: the host
/// process's global exports in interpose builds, or the owned loader's runtime
/// exports in standalone builds. Never mix the two allocation namespaces.
#[cfg(not(feature = "standalone"))]
fn global_allocator() -> Option<(MallocFn, FreeFn)> {
    let default = libc::RTLD_DEFAULT as usize;
    let malloc = module_dlsym(default, c"malloc");
    let free = module_dlsym(default, c"free");
    if malloc == 0 || free == 0 {
        return None;
    }
    // SAFETY: these exports have the malloc and free ABIs in the same loader
    // namespace used to bind the module's realloc.
    unsafe {
        Some((
            core::mem::transmute::<usize, MallocFn>(malloc),
            core::mem::transmute::<usize, FreeFn>(free),
        ))
    }
}

#[cfg(feature = "standalone")]
fn global_allocator() -> Option<(MallocFn, FreeFn)> {
    // These exact frontends also bind native DSO malloc/realloc/free imports.
    Some((crate::malloc_abi::malloc, crate::malloc_abi::free))
}

/// One module's contribution to a user's supplementary groups: its gids
/// (excluding `base`) and its status. Uses `_nss_<service>_initgroups_dyn`
/// when the module has it, else walks the module's group enumeration.
pub(crate) fn initgroups_segment(
    service: &[u8],
    user: &[u8],
    base: u32,
    current: &[u32],
    limit: c_long,
) -> (Status, Vec<u32>) {
    if let Some(addr) = module_function(service, "initgroups_dyn") {
        return initgroups_dyn(addr, user, base, current, limit);
    }
    initgroups_by_enumeration(service, user, base)
}

fn initgroups_dyn(
    addr: usize,
    user: &[u8],
    base: u32,
    current: &[u32],
    limit: c_long,
) -> (Status, Vec<u32>) {
    let Some((malloc, free)) = global_allocator() else {
        return (Status::Unavailable, Vec::new());
    };
    let capacity = current.len().max(1) + 32;
    // SAFETY: plain allocation of `capacity` gids from the global allocator,
    // which the module's realloc also uses.
    let array = unsafe { malloc(capacity * std::mem::size_of::<u32>()) }.cast::<u32>();
    if array.is_null() {
        return (Status::TryAgain, Vec::new());
    }
    // SAFETY: `array` holds `capacity` >= current.len() gids.
    unsafe { std::ptr::copy_nonoverlapping(current.as_ptr(), array, current.len()) };
    let mut start: c_long = current.len() as c_long;
    let mut size: c_long = capacity as c_long;
    let mut groups = array;
    let mut err: c_int = 0;
    let mut user_c = user.to_vec();
    user_c.push(0);
    // SAFETY: the entry point has the documented initgroups_dyn signature;
    // start/size/groups describe a malloc'd array the module may realloc.
    let f: InitgroupsDynFn = unsafe { core::mem::transmute(addr) };
    let status = Status::from_raw(unsafe {
        f(
            user_c.as_ptr().cast(),
            base,
            &mut start,
            &mut size,
            &mut groups,
            limit,
            &mut err,
        )
    });
    let mut segment = Vec::new();
    if !groups.is_null() {
        let end = (start.max(0) as usize).min(size.max(0) as usize);
        for index in current.len()..end {
            // SAFETY: indices below `start` (<= size) are initialized gids.
            segment.push(unsafe { *groups.add(index) });
        }
        // SAFETY: the array came from (and was possibly resized by) the global allocator.
        unsafe { free(groups.cast()) };
    }
    (status, segment)
}

fn initgroups_by_enumeration(service: &[u8], user: &[u8], base: u32) -> (Status, Vec<u32>) {
    if module_function(service, "getgrent_r").is_none() {
        return (Status::Unavailable, Vec::new());
    }
    let status = call_setent(service, "setgrent");
    if status != Status::Success {
        return (status, Vec::new());
    }
    let mut segment = Vec::new();
    while let Answer::Found(group) = getgrent(service) {
        if group.gr_gid != base
            && group.gr_mem.iter().any(|m| m.as_slice() == user)
            && !segment.contains(&group.gr_gid)
        {
            segment.push(group.gr_gid);
        }
    }
    call_endent(service, "endgrent");
    (Status::Success, segment)
}
