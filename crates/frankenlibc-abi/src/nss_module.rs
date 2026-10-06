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
//! fingerprint), loading modules once per process through the host dynamic
//! loader, and calling the reentrant entry points with a growing scratch
//! buffer, converting each result into fl's owned entry types. The policy --
//! source order, status actions, group merge, initgroups de-duplication --
//! lives in `frankenlibc_core::nss`.
//!
//! Loading needs the host dynamic loader, so standalone builds report every
//! module source as unavailable (the switch then continues per its actions).

use std::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};

use frankenlibc_core::nss::{Answer, Database, Service, SourceKind, Status};

const NSSWITCH_PATH: &str = "/etc/nsswitch.conf";
const NSSWITCH_PATH_ENV: &str = "FRANKENLIBC_NSSWITCH_CONF";

/// Scratch buffer for a module call starts here and doubles on ERANGE.
const INITIAL_SCRATCH: usize = 1024;
/// Give up growing (report TRYAGAIN/ERANGE as unavailable) past this size.
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
    parsed: [Option<Arc<Vec<Service>>>; 4],
    /// Whether the image has its own `initgroups:` line.
    initgroups_explicit: Option<bool>,
}

static CONFIG: Mutex<ConfigCache> = Mutex::new(ConfigCache {
    path: Vec::new(),
    fingerprint: None,
    loaded: false,
    parsed: [None, None, None, None],
    initgroups_explicit: None,
});

fn database_slot(database: Database) -> usize {
    match database {
        Database::Passwd => 0,
        Database::Group => 1,
        Database::Shadow => 2,
        Database::Initgroups => 3,
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
/// re-parsed whenever its fingerprint changes; a missing or unreadable file
/// means glibc's built-in default (`files`).
pub(crate) fn services(database: Database) -> Arc<Vec<Service>> {
    let slot = database_slot(database);
    with_current_config(|cache, read| {
        if let Some(parsed) = &cache.parsed[slot] {
            return Arc::clone(parsed);
        }
        let content = read(cache);
        let parsed = Arc::new(frankenlibc_core::nss::services_for(
            content.as_deref(),
            database,
        ));
        cache.parsed[slot] = Some(Arc::clone(&parsed));
        parsed
    })
}

/// Whether nsswitch.conf has its own `initgroups:` line, which changes how
/// SUCCESS is treated (see `frankenlibc_core::nss::initgroups_stops`).
pub(crate) fn initgroups_line_explicit() -> bool {
    with_current_config(|cache, read| {
        if let Some(explicit) = cache.initgroups_explicit {
            return explicit;
        }
        let content = read(cache);
        let explicit =
            frankenlibc_core::nss::has_database_line(content.as_deref(), Database::Initgroups);
        cache.initgroups_explicit = Some(explicit);
        explicit
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
    if !(cache.loaded && cache.path == path && cache.fingerprint == now) {
        cache.path = path;
        cache.fingerprint = now;
        cache.loaded = true;
        cache.parsed = [None, None, None, None];
        cache.initgroups_explicit = None;
    }
    fn read(cache: &ConfigCache) -> Option<Vec<u8>> {
        use std::os::unix::ffi::OsStrExt;
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
    /// Host dlopen handle; 0 when the module could not be loaded.
    handle: usize,
    /// Resolved entry points (function name, address; 0 = absent).
    symbols: Vec<(&'static str, usize)>,
}

static MODULES: Mutex<Vec<LoadedModule>> = Mutex::new(Vec::new());

#[cfg(not(feature = "standalone"))]
fn host_dlopen(path: &CStr) -> usize {
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
fn host_dlopen(_path: &CStr) -> usize {
    0
}

#[cfg(not(feature = "standalone"))]
fn host_dlsym(handle: usize, name: &CStr) -> usize {
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
fn host_dlsym(_handle: usize, _name: &CStr) -> usize {
    0
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
/// The table lock is never held across the host `dlopen`/`dlsym`: a module's
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
        let opened = CStr::from_bytes_with_nul(&path).map_or(0, host_dlopen);
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
    let addr = CStr::from_bytes_with_nul(&symbol).map_or(0, |name| host_dlsym(handle, name));
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

/// The allocator a module's `realloc` of the group array binds to: the
/// process's global `malloc`/`realloc`/`free` (fl's own when preloaded).
fn global_allocator() -> Option<(MallocFn, FreeFn)> {
    let default = libc::RTLD_DEFAULT as usize;
    let malloc = host_dlsym(default, c"malloc");
    let free = host_dlsym(default, c"free");
    if malloc == 0 || free == 0 {
        return None;
    }
    // SAFETY: these are the process's malloc and free.
    unsafe {
        Some((
            core::mem::transmute::<usize, MallocFn>(malloc),
            core::mem::transmute::<usize, FreeFn>(free),
        ))
    }
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
