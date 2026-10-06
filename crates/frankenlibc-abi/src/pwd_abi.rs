//! ABI layer for `<pwd.h>` functions.
//!
//! Implements `getpwnam`, `getpwuid`, `getpwent`, `setpwent`, `endpwent`
//! using a files backend (parsing `/etc/passwd`).
//!
//! Returns pointers to thread-local static storage, matching glibc behavior
//! where each call overwrites the previous result.

use std::cell::{Cell, RefCell};
use std::ffi::{CString, c_char, c_int, c_void};
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::UNIX_EPOCH;

use frankenlibc_core::errno;
use frankenlibc_core::nss::{Answer, Database, Service, SourceKind, Status};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::nss_module::{self, EntCursor, EntDb, EntStep};
use crate::runtime_policy;
use crate::util::scan_c_string;

const PASSWD_PATH: &str = "/etc/passwd";
const PASSWD_PATH_ENV: &str = "FRANKENLIBC_PASSWD_PATH";

unsafe fn bounded_cstr_bytes<'a>(ptr: *const c_char) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr is a caller-provided C string; known_remaining bounds scans
    // over tracked malloc-backed buffers before they can cross allocation end.
    let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    // SAFETY: scan_c_string observed len readable bytes before the terminator.
    Some(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) })
}

fn tracked_object_fits<T>(ptr: *const T) -> bool {
    (ptr as usize) & (std::mem::align_of::<T>() - 1) == 0
        && known_remaining(ptr as usize)
            .is_none_or(|remaining| remaining >= std::mem::size_of::<T>())
}

fn effective_buffer_len(ptr: *const c_char, requested: libc::size_t) -> libc::size_t {
    known_remaining(ptr as usize).map_or(requested, |remaining| remaining.min(requested))
}

fn passwd_buffer_needed(entry: &frankenlibc_core::pwd::Passwd) -> Option<usize> {
    entry
        .pw_name
        .len()
        .checked_add(1)?
        .checked_add(entry.pw_passwd.len())?
        .checked_add(1)?
        .checked_add(entry.pw_gecos.len())?
        .checked_add(1)?
        .checked_add(entry.pw_dir.len())?
        .checked_add(1)?
        .checked_add(entry.pw_shell.len())?
        .checked_add(1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    modified_ns: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct CacheMetrics {
    hits: u64,
    misses: u64,
    reloads: u64,
    invalidations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedUidLookup {
    uid: u32,
    generation: u64,
    entry: frankenlibc_core::pwd::Passwd,
}

/// Thread-local storage for the most recent passwd result.
/// Holds the C-layout struct plus backing string buffers.
struct PwdStorage {
    pw: libc::passwd,
    /// Concatenated NUL-terminated strings backing the passwd fields.
    buf: Vec<u8>,
    /// File path for passwd backend (defaults to /etc/passwd).
    source_path: PathBuf,
    /// Cached C-compatible source path for the hot fingerprint probe.
    source_path_cstr: Option<CString>,
    /// Cached file content.
    file_cache: Option<Vec<u8>>,
    /// Fingerprint for the cached file snapshot.
    cache_fingerprint: Option<FileFingerprint>,
    /// Monotonic generation for cache reloads.
    cache_generation: u64,
    /// Generation used to build `entries`.
    entries_generation: u64,
    /// Parsed entries for iteration.
    entries: Vec<frankenlibc_core::pwd::Passwd>,
    /// Parse accounting from the most recent `entries` build.
    #[allow(dead_code)]
    last_parse_stats: frankenlibc_core::pwd::ParseStats,
    /// Current iteration index for getpwent.
    iter_idx: usize,
    /// Cache hit/miss/reload/invalidation counters.
    cache_metrics: CacheMetrics,
    /// Most recent backend I/O error encountered while refreshing the cache.
    last_io_error: Option<c_int>,
    /// Last successful uid lookup for this cached file generation.
    last_uid_lookup: Option<CachedUidLookup>,
    /// The uid/generation currently materialized in `pw` and `buf`, when it
    /// came from `fill_uid_lookup`.
    current_uid_result: Option<(u32, u64)>,
}

#[cfg(feature = "owned-tls-cache")]
// SAFETY: PwdStorage is accessed through OwnedTlsCache, which serializes access
// and keeps each per-thread value boxed. The raw pointers stored in `pw` only
// point into the same boxed PwdStorage buffer and are refreshed before they are
// returned to callers.
unsafe impl Send for PwdStorage {}

impl PwdStorage {
    fn new() -> Self {
        Self::new_with_path(Self::configured_source_path())
    }

    fn new_with_path(path: impl Into<PathBuf>) -> Self {
        let source_path = path.into();
        let source_path_cstr = Self::path_cstring(&source_path);
        Self {
            pw: unsafe { std::mem::zeroed() },
            buf: Vec::new(),
            source_path,
            source_path_cstr,
            file_cache: None,
            cache_fingerprint: None,
            cache_generation: 0,
            entries_generation: 0,
            entries: Vec::new(),
            last_parse_stats: frankenlibc_core::pwd::ParseStats::default(),
            iter_idx: 0,
            cache_metrics: CacheMetrics::default(),
            last_io_error: None,
            last_uid_lookup: None,
            current_uid_result: None,
        }
    }

    fn path_cstring(path: &Path) -> Option<CString> {
        CString::new(path.as_os_str().as_bytes()).ok()
    }

    fn configured_source_path() -> PathBuf {
        std::env::var_os(PASSWD_PATH_ENV)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(PASSWD_PATH))
    }

    fn refresh_source_path_from_env(&mut self) {
        let configured = Self::configured_source_path();
        if configured == self.source_path {
            return;
        }

        self.source_path = configured;
        self.source_path_cstr = Self::path_cstring(&self.source_path);
        if self.file_cache.is_some() || !self.entries.is_empty() {
            self.cache_metrics.invalidations += 1;
        }
        self.file_cache = None;
        self.cache_fingerprint = None;
        self.entries.clear();
        self.clear_lookup_cache();
        self.iter_idx = 0;
        self.entries_generation = 0;
        self.last_parse_stats = frankenlibc_core::pwd::ParseStats::default();
        self.last_io_error = None;
    }

    fn file_fingerprint_cstr(path: &CString) -> Option<FileFingerprint> {
        let mut statbuf = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `path` is NUL-terminated and `statbuf` points to valid,
        // writable storage for libc to initialize.
        // Raw syscall, not `libc::stat` and not fl's own `stat()`. `libc::stat`
        // is a host call-through the replacement guard forbids -- and in a
        // release build it already binds to fl's export anyway, so it bought
        // nothing. fl's `stat()` would work but adds a decide/observe pair per
        // call for an internal cache check that no caller can observe.
        let rc = match unsafe {
            frankenlibc_core::syscall::sys_newfstatat(
                libc::AT_FDCWD,
                path.as_ptr() as *const u8,
                statbuf.as_mut_ptr() as *mut u8,
                0,
            )
        } {
            Ok(()) => 0,
            Err(_) => -1,
        };
        if rc != 0 {
            return None;
        }

        // SAFETY: libc::stat returned success, so the whole stat buffer is initialized.
        let statbuf = unsafe { statbuf.assume_init() };
        let len = u64::try_from(statbuf.st_size).ok()?;
        let sec = u128::try_from(statbuf.st_mtime).ok()?;
        let nsec = u128::try_from(statbuf.st_mtime_nsec).ok()?;

        Some(FileFingerprint {
            len,
            modified_ns: sec.saturating_mul(1_000_000_000).saturating_add(nsec),
        })
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
        })
    }

    fn current_file_fingerprint(&self, prefer_c_stat: bool) -> Option<FileFingerprint> {
        if prefer_c_stat {
            self.source_path_cstr
                .as_ref()
                .and_then(Self::file_fingerprint_cstr)
                .or_else(|| Self::file_fingerprint(&self.source_path))
        } else {
            Self::file_fingerprint(&self.source_path)
        }
    }

    /// Refresh cache from disk when fingerprint changes.
    ///
    /// Invalidation policy:
    /// - cache hit: retain parsed entries/cursor
    /// - reload or read failure: drop parsed entries and reset cursor
    fn refresh_cache(&mut self) {
        self.refresh_cache_with_probe(false);
    }

    fn refresh_cache_fast_stat(&mut self) {
        self.refresh_cache_with_probe(true);
    }

    fn refresh_cache_with_probe(&mut self, prefer_c_stat: bool) {
        self.refresh_source_path_from_env();
        let current_fp = self.current_file_fingerprint(prefer_c_stat);

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
                let next_fp = self
                    .current_file_fingerprint(prefer_c_stat)
                    .or(current_fp)
                    .unwrap_or(FileFingerprint {
                        len: bytes.len() as u64,
                        modified_ns: 0,
                    });
                let had_cache = self.file_cache.is_some();

                self.file_cache = Some(bytes);
                self.cache_fingerprint = Some(next_fp);
                self.cache_generation = self.cache_generation.wrapping_add(1);
                self.cache_metrics.reloads += 1;
                self.last_io_error = None;

                if had_cache {
                    self.entries.clear();
                    self.clear_lookup_cache();
                    self.iter_idx = 0;
                    self.entries_generation = 0;
                    self.last_parse_stats = frankenlibc_core::pwd::ParseStats::default();
                    self.cache_metrics.invalidations += 1;
                }
            }
            Err(err) => {
                if self.file_cache.is_some() || !self.entries.is_empty() {
                    self.cache_metrics.invalidations += 1;
                }
                self.file_cache = None;
                self.cache_fingerprint = None;
                self.entries.clear();
                self.clear_lookup_cache();
                self.iter_idx = 0;
                self.entries_generation = 0;
                self.last_parse_stats = frankenlibc_core::pwd::ParseStats::default();
                self.last_io_error = Some(err.raw_os_error().unwrap_or(errno::EIO));
            }
        }
    }

    fn current_content(&self) -> &[u8] {
        self.file_cache.as_deref().unwrap_or_default()
    }

    fn backend_io_error(&self) -> Option<c_int> {
        if self.file_cache.is_none() {
            self.last_io_error
        } else {
            None
        }
    }

    fn rebuild_entries(&mut self) {
        let (entries, stats) = frankenlibc_core::pwd::parse_all_with_stats(self.current_content());
        self.entries = entries;
        self.last_parse_stats = stats;
        self.iter_idx = 0;
        self.entries_generation = self.cache_generation;
    }

    fn clear_lookup_cache(&mut self) {
        self.last_uid_lookup = None;
        self.current_uid_result = None;
    }

    fn lookup_by_uid_cached(&mut self, uid: u32) -> Option<frankenlibc_core::pwd::Passwd> {
        self.refresh_cache_fast_stat();
        if let Some(cached) = &self.last_uid_lookup
            && cached.uid == uid
            && cached.generation == self.cache_generation
        {
            return Some(cached.entry.clone());
        }

        let entry = frankenlibc_core::pwd::lookup_by_uid(self.current_content(), uid)?;
        self.last_uid_lookup = Some(CachedUidLookup {
            uid,
            generation: self.cache_generation,
            entry: entry.clone(),
        });
        Some(entry)
    }

    fn fill_uid_lookup(&mut self, uid: u32) -> *mut libc::passwd {
        self.refresh_cache_fast_stat();
        if let Some(cached) = &self.last_uid_lookup
            && cached.uid == uid
            && cached.generation == self.cache_generation
        {
            if self.current_uid_result == Some((uid, self.cache_generation)) {
                return &mut self.pw as *mut libc::passwd;
            }

            let entry = cached.entry.clone();
            let result = self.fill_from(&entry);
            self.current_uid_result = Some((uid, self.cache_generation));
            return result;
        }

        match frankenlibc_core::pwd::lookup_by_uid(self.current_content(), uid) {
            Some(entry) => {
                self.last_uid_lookup = Some(CachedUidLookup {
                    uid,
                    generation: self.cache_generation,
                    entry: entry.clone(),
                });
                let result = self.fill_from(&entry);
                self.current_uid_result = Some((uid, self.cache_generation));
                result
            }
            None => {
                self.current_uid_result = None;
                ptr::null_mut()
            }
        }
    }

    /// Populate the C struct from a parsed entry.
    /// Returns a pointer to the thread-local `libc::passwd`.
    fn fill_from(&mut self, entry: &frankenlibc_core::pwd::Passwd) -> *mut libc::passwd {
        self.current_uid_result = None;

        // Colon-less NIS compat markers have NULL non-name fields in glibc,
        // not pointers to empty strings.
        self.buf.clear();
        let name_off = 0;
        self.buf.extend_from_slice(&entry.pw_name);
        self.buf.push(0);
        let append_field = |buf: &mut Vec<u8>, field: &[u8]| {
            let offset = buf.len();
            buf.extend_from_slice(field);
            buf.push(0);
            offset
        };
        let passwd_off =
            (!entry.nis_compat_null_fields).then(|| append_field(&mut self.buf, &entry.pw_passwd));
        let gecos_off =
            (!entry.nis_compat_null_fields).then(|| append_field(&mut self.buf, &entry.pw_gecos));
        let dir_off =
            (!entry.nis_compat_null_fields).then(|| append_field(&mut self.buf, &entry.pw_dir));
        let shell_off =
            (!entry.nis_compat_null_fields).then(|| append_field(&mut self.buf, &entry.pw_shell));

        let base = self.buf.as_ptr() as *mut c_char;
        // SAFETY: offsets are within the buf allocation. Pointers are stable
        // because we don't resize buf again until the next fill_from call.
        self.pw = libc::passwd {
            pw_name: unsafe { base.add(name_off) },
            pw_passwd: passwd_off.map_or(ptr::null_mut(), |off| unsafe { base.add(off) }),
            pw_uid: entry.pw_uid,
            pw_gid: entry.pw_gid,
            pw_gecos: gecos_off.map_or(ptr::null_mut(), |off| unsafe { base.add(off) }),
            pw_dir: dir_off.map_or(ptr::null_mut(), |off| unsafe { base.add(off) }),
            pw_shell: shell_off.map_or(ptr::null_mut(), |off| unsafe { base.add(off) }),
        };

        &mut self.pw as *mut libc::passwd
    }
}

#[cfg(feature = "owned-tls-cache")]
static PWD_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<PwdStorage> =
    crate::owned_tls_cache::OwnedTlsCache::new(PwdStorage::new);

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static PWD_TLS: RefCell<PwdStorage> = RefCell::new(PwdStorage::new());
}

fn with_pwd_storage<R>(callback: impl FnOnce(&mut PwdStorage) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        PWD_OWNED_TLS.with(callback)
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        PWD_TLS.with(|cell| {
            let mut storage = cell.borrow_mut();
            callback(&mut storage)
        })
    }
}

/// Fill thread-local passwd struct from a parsed entry.
/// Used by `fgetpwent` in `unistd_abi` to avoid duplicating TLS storage.
pub(crate) fn fill_passwd_from_entry(entry: &frankenlibc_core::pwd::Passwd) -> *mut libc::passwd {
    with_pwd_storage(|storage| storage.fill_from(entry))
}

pub(crate) fn lookup_passwd_by_name(name: &[u8]) -> Option<frankenlibc_core::pwd::Passwd> {
    match passwd_answer(PwKey::Name(name), None) {
        Answer::Found(entry) => Some(entry),
        _ => None,
    }
}

pub(crate) fn lookup_passwd_by_uid(uid: u32) -> Option<frankenlibc_core::pwd::Passwd> {
    match passwd_answer(PwKey::Uid(uid), None) {
        Answer::Found(entry) => Some(entry),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Name Service Switch dispatch
// ---------------------------------------------------------------------------
//
// nsswitch.conf's `passwd:` line picks the sources. `files` (and `compat`)
// run the native backend above; any other source is a `libnss_<name>.so.2`
// module (sss, systemd, ldap, winbind, ...). The default single `files`
// source keeps the cached fast paths.

#[derive(Clone, Copy)]
enum PwKey<'a> {
    Name(&'a [u8]),
    Uid(u32),
}

/// The files source. `buffer` is the caller's buffer length for the `_r`
/// entry points, whose files lookups glibc runs inside that buffer.
fn files_passwd_answer(
    key: PwKey<'_>,
    buffer: Option<usize>,
) -> Answer<frankenlibc_core::pwd::Passwd> {
    with_pwd_storage(|storage| {
        let found = match key {
            PwKey::Name(name) => {
                storage.refresh_cache();
                frankenlibc_core::pwd::lookup_by_name(storage.current_content(), name)
            }
            PwKey::Uid(uid) => storage.lookup_by_uid_cached(uid),
        };
        // Same snapshot the lookup just used.
        if buffer.is_some_and(|buflen| {
            frankenlibc_core::pwd::files_lookup_exceeds_buffer(
                storage.current_content(),
                buflen,
                |entry| match key {
                    PwKey::Name(name) => entry.pw_name == name,
                    PwKey::Uid(uid) => entry.pw_uid == uid,
                },
            )
        }) {
            return Answer::BufferTooSmall;
        }
        match found {
            Some(entry) => Answer::Found(entry),
            None => match storage.backend_io_error() {
                Some(err) => Answer::Unavailable(err),
                None => Answer::NotFound,
            },
        }
    })
}

fn passwd_switch(
    services: &[Service],
    key: PwKey<'_>,
    buffer: Option<usize>,
) -> Answer<frankenlibc_core::pwd::Passwd> {
    if nss_module::is_files_only(services) {
        return files_passwd_answer(key, buffer);
    }
    frankenlibc_core::nss::lookup(
        services,
        |service| match service.kind() {
            SourceKind::Files => files_passwd_answer(key, buffer),
            SourceKind::Module => match key {
                PwKey::Name(name) => nss_module::getpwnam(service.name(), name),
                PwKey::Uid(uid) => nss_module::getpwuid(service.name(), uid),
            },
        },
        None,
    )
}

fn passwd_answer(key: PwKey<'_>, buffer: Option<usize>) -> Answer<frankenlibc_core::pwd::Passwd> {
    passwd_switch(&nss_module::services(Database::Passwd), key, buffer)
}

/// A non-reentrant lookup's result in thread-local storage, or NULL with the
/// errno to report (`None` leaves errno alone, as a plain miss does).
fn static_passwd(
    answer: Answer<frankenlibc_core::pwd::Passwd>,
) -> (*mut libc::passwd, Option<c_int>) {
    match answer {
        Answer::Found(entry) => (fill_passwd_from_entry(&entry), None),
        Answer::NotFound => (ptr::null_mut(), None),
        Answer::Unavailable(err) | Answer::TryAgain(err) => (ptr::null_mut(), Some(err)),
        Answer::BufferTooSmall => (ptr::null_mut(), Some(libc::ERANGE)),
    }
}

/// A reentrant lookup's return code: fill the caller's buffers on success.
///
/// # Safety
/// As for [`fill_passwd_r`].
unsafe fn reentrant_passwd(
    answer: Answer<frankenlibc_core::pwd::Passwd>,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::passwd,
) -> c_int {
    match answer {
        // SAFETY: forwarded caller contract.
        Answer::Found(entry) => unsafe {
            fill_passwd_r(&entry, pwd, buf, effective_buffer_len(buf, buflen), result)
        },
        Answer::NotFound => 0,
        Answer::Unavailable(err) | Answer::TryAgain(err) => err,
        Answer::BufferTooSmall => libc::ERANGE,
    }
}

impl PwdStorage {
    /// The next entry of a files source being enumerated as one source among
    /// several; `restart` begins a fresh snapshot.
    fn next_files_entry(&mut self, restart: bool) -> Answer<frankenlibc_core::pwd::Passwd> {
        self.refresh_cache();
        if restart || self.entries_generation != self.cache_generation {
            self.rebuild_entries();
        }
        if let Some(entry) = self.entries.get(self.iter_idx).cloned() {
            self.iter_idx += 1;
            return Answer::Found(entry);
        }
        match self.backend_io_error() {
            Some(err) => Answer::Unavailable(err),
            None => Answer::NotFound,
        }
    }
}

thread_local! {
    /// Multi-source `getpwent` position, and an entry `getpwent_r` could not
    /// fit into the caller's buffer (returned again on the next call).
    static PW_ENT: Cell<EntCursor> = const { Cell::new(EntCursor { source: 0, started: false }) };
    static PW_PENDING: RefCell<Option<frankenlibc_core::pwd::Passwd>> = const { RefCell::new(None) };
}

/// Next entry of a multi-source enumeration: `Err(None)` at the end,
/// `Err(Some(errno))` when a source failed and its action ends the walk.
fn next_passwd_entry() -> Result<frankenlibc_core::pwd::Passwd, Option<c_int>> {
    if let Some(entry) = PW_PENDING.with(|p| p.borrow_mut().take()) {
        return Ok(entry);
    }
    loop {
        let mut cursor = PW_ENT.with(Cell::get);
        let (step, service) =
            nss_module::ent_step(EntDb::Passwd, &mut cursor, nss_module::getpwent);
        PW_ENT.with(|c| c.set(cursor));
        let answer = match step {
            EntStep::Done => return Err(None),
            EntStep::Files { restart } => with_pwd_storage(|s| s.next_files_entry(restart)),
            EntStep::Module(answer) => answer,
        };
        let (status, err) = match answer {
            Answer::Found(entry) => return Ok(entry),
            Answer::NotFound => (Status::NotFound, None),
            Answer::TryAgain(err) => (Status::TryAgain, Some(err)),
            Answer::Unavailable(err) => (Status::Unavailable, Some(err)),
            Answer::BufferTooSmall => (Status::Unavailable, Some(libc::ERANGE)),
        };
        let Some(service) = service else {
            return Err(None);
        };
        let mut cursor = PW_ENT.with(Cell::get);
        let advanced = nss_module::ent_advance(&mut cursor, &service, status);
        PW_ENT.with(|c| c.set(cursor));
        if !advanced {
            return Err(err);
        }
    }
}

fn reset_passwd_enumeration() {
    PW_ENT.with(|c| c.set(EntCursor::default()));
    PW_PENDING.with(|p| *p.borrow_mut() = None);
}

fn passwd_backend_io_error() -> Option<c_int> {
    with_pwd_storage(|storage| storage.backend_io_error())
}

/// Read /etc/passwd and look up by name, returning a pointer to thread-local storage.
fn do_getpwnam(name: &[u8]) -> *mut libc::passwd {
    with_pwd_storage(|storage| {
        storage.refresh_cache();
        match frankenlibc_core::pwd::lookup_by_name(storage.current_content(), name) {
            Some(entry) => storage.fill_from(&entry),
            None => ptr::null_mut(),
        }
    })
}

/// Read /etc/passwd and look up by uid, returning a pointer to thread-local storage.
fn do_getpwuid(uid: u32) -> *mut libc::passwd {
    with_pwd_storage(|storage| storage.fill_uid_lookup(uid))
}

/// POSIX `getpwnam` — look up passwd entry by username.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpwnam(name: *const c_char) -> *mut libc::passwd {
    if name.is_null() {
        return ptr::null_mut();
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Resolver, name as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    let Some(name_bytes) = (unsafe { bounded_cstr_bytes(name) }) else {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    };
    let services = nss_module::services(Database::Passwd);
    let (result, err) = if nss_module::is_files_only(&services) {
        let result = do_getpwnam(name_bytes);
        (
            result,
            result.is_null().then(passwd_backend_io_error).flatten(),
        )
    } else {
        static_passwd(passwd_switch(&services, PwKey::Name(name_bytes), None))
    };
    if let Some(err) = err {
        unsafe { set_abi_errno(err) };
    }
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, result.is_null());
    result
}

/// POSIX `getpwuid` — look up passwd entry by user ID.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpwuid(uid: libc::uid_t) -> *mut libc::passwd {
    let (_, decision) = runtime_policy::decide(ApiFamily::Resolver, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    let services = nss_module::services(Database::Passwd);
    let (result, err) = if nss_module::is_files_only(&services) {
        let result = do_getpwuid(uid);
        (
            result,
            result.is_null().then(passwd_backend_io_error).flatten(),
        )
    } else {
        static_passwd(passwd_switch(&services, PwKey::Uid(uid), None))
    };
    if let Some(err) = err {
        unsafe { set_abi_errno(err) };
    }
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, result.is_null());
    result
}

/// POSIX `setpwent` — rewind the passwd iteration cursor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpwent() {
    reset_passwd_enumeration();
    with_pwd_storage(|storage| {
        storage.refresh_cache();
        storage.rebuild_entries();
    });
}

/// POSIX `endpwent` — close the passwd enumeration and free cached data.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endpwent() {
    reset_passwd_enumeration();
    if !nss_module::is_files_only(&nss_module::services(Database::Passwd)) {
        nss_module::ent_end(EntDb::Passwd);
    }
    with_pwd_storage(|storage| {
        if storage.file_cache.is_some() || !storage.entries.is_empty() {
            storage.cache_metrics.invalidations += 1;
        }
        storage.entries.clear();
        storage.clear_lookup_cache();
        storage.iter_idx = 0;
        storage.file_cache = None;
        storage.cache_fingerprint = None;
        storage.entries_generation = 0;
        storage.last_parse_stats = frankenlibc_core::pwd::ParseStats::default();
    });
}

/// POSIX `getpwent` — return the next passwd entry in iteration order.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpwent() -> *mut libc::passwd {
    if !nss_module::is_files_only(&nss_module::services(Database::Passwd)) {
        return match next_passwd_entry() {
            Ok(entry) => fill_passwd_from_entry(&entry),
            Err(err) => {
                if let Some(err) = err {
                    unsafe { set_abi_errno(err) };
                }
                ptr::null_mut()
            }
        };
    }
    with_pwd_storage(|storage| {
        storage.refresh_cache();

        // If entries haven't been loaded, call setpwent implicitly.
        if (storage.entries.is_empty() && storage.iter_idx == 0)
            || storage.entries_generation != storage.cache_generation
        {
            storage.rebuild_entries();
        }

        if storage.iter_idx >= storage.entries.len() {
            if let Some(err) = storage.backend_io_error() {
                unsafe { set_abi_errno(err) };
            }
            return ptr::null_mut();
        }

        let entry = storage.entries[storage.iter_idx].clone();
        storage.iter_idx += 1;
        storage.fill_from(&entry)
    })
}

/// POSIX `getpwnam_r` — reentrant version of `getpwnam`.
///
/// Writes the result into caller-supplied `pwd` and `buf`, storing a pointer
/// to the result in `*result` on success.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpwnam_r(
    name: *const c_char,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::passwd,
) -> c_int {
    if name.is_null() || pwd.is_null() || buf.is_null() || result.is_null() {
        return libc::EINVAL;
    }
    if !tracked_object_fits(result as *const *mut libc::passwd) {
        return libc::EINVAL;
    }

    // SAFETY: result is non-null.
    unsafe { *result = ptr::null_mut() };
    if !tracked_object_fits(pwd as *const libc::passwd) {
        return libc::EINVAL;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Resolver, name as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return libc::EACCES;
    }

    let Some(name_bytes) = (unsafe { bounded_cstr_bytes(name) }) else {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return libc::EINVAL;
    };

    // A miss leaves *result NULL and returns 0.
    let answer = passwd_answer(
        PwKey::Name(name_bytes),
        Some(effective_buffer_len(buf, buflen)),
    );
    let rc = unsafe { reentrant_passwd(answer, pwd, buf, buflen, result) };
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, rc != 0);
    rc
}

/// POSIX `getpwuid_r` — reentrant version of `getpwuid`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpwuid_r(
    uid: libc::uid_t,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::passwd,
) -> c_int {
    if pwd.is_null() || buf.is_null() || result.is_null() {
        return libc::EINVAL;
    }
    if !tracked_object_fits(result as *const *mut libc::passwd) {
        return libc::EINVAL;
    }

    // SAFETY: result is non-null.
    unsafe { *result = ptr::null_mut() };
    if !tracked_object_fits(pwd as *const libc::passwd) {
        return libc::EINVAL;
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Resolver, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return libc::EACCES;
    }

    let answer = passwd_answer(PwKey::Uid(uid), Some(effective_buffer_len(buf, buflen)));
    let rc = unsafe { reentrant_passwd(answer, pwd, buf, buflen, result) };
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, rc != 0);
    rc
}

/// Fill a caller-provided `libc::passwd` and string buffer for `_r` variants.
///
/// # Safety
///
/// `pwd`, `buf`, `result` must be valid writable pointers. `buflen` must be
/// capped to the actual writable size of `buf`.
unsafe fn fill_passwd_r(
    entry: &frankenlibc_core::pwd::Passwd,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::passwd,
) -> c_int {
    // Calculate needed buffer: name\0passwd\0gecos\0dir\0shell\0
    let Some(needed) = passwd_buffer_needed(entry) else {
        return libc::ERANGE;
    };

    if buflen < needed {
        return libc::ERANGE;
    }

    let mut off = 0usize;
    let base = buf;

    // SAFETY: all writes are within [buf, buf+buflen) since needed <= buflen.
    unsafe {
        // pw_name
        let name_ptr = base.add(off);
        ptr::copy_nonoverlapping(
            entry.pw_name.as_ptr().cast::<c_char>(),
            name_ptr,
            entry.pw_name.len(),
        );
        *base.add(off + entry.pw_name.len()) = 0;
        off += entry.pw_name.len() + 1;

        // pw_passwd
        let passwd_ptr = base.add(off);
        ptr::copy_nonoverlapping(
            entry.pw_passwd.as_ptr().cast::<c_char>(),
            passwd_ptr,
            entry.pw_passwd.len(),
        );
        *base.add(off + entry.pw_passwd.len()) = 0;
        off += entry.pw_passwd.len() + 1;

        // pw_gecos
        let gecos_ptr = base.add(off);
        ptr::copy_nonoverlapping(
            entry.pw_gecos.as_ptr().cast::<c_char>(),
            gecos_ptr,
            entry.pw_gecos.len(),
        );
        *base.add(off + entry.pw_gecos.len()) = 0;
        off += entry.pw_gecos.len() + 1;

        // pw_dir
        let dir_ptr = base.add(off);
        ptr::copy_nonoverlapping(
            entry.pw_dir.as_ptr().cast::<c_char>(),
            dir_ptr,
            entry.pw_dir.len(),
        );
        *base.add(off + entry.pw_dir.len()) = 0;
        off += entry.pw_dir.len() + 1;

        // pw_shell
        let shell_ptr = base.add(off);
        ptr::copy_nonoverlapping(
            entry.pw_shell.as_ptr().cast::<c_char>(),
            shell_ptr,
            entry.pw_shell.len(),
        );
        *base.add(off + entry.pw_shell.len()) = 0;

        (*pwd) = libc::passwd {
            pw_name: name_ptr,
            pw_passwd: passwd_ptr,
            pw_uid: entry.pw_uid,
            pw_gid: entry.pw_gid,
            pw_gecos: gecos_ptr,
            pw_dir: dir_ptr,
            pw_shell: shell_ptr,
        };

        *result = pwd;
    }

    0
}

/// GNU `getpwent_r` — reentrant version of `getpwent`.
///
/// Iterates through `/etc/passwd` entries, filling a caller-provided buffer.
/// Returns 0 on success, `ENOENT` at end of file, `ERANGE` if buffer too small.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpwent_r(
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::passwd,
) -> c_int {
    if pwd.is_null() || buf.is_null() || result.is_null() {
        return libc::EINVAL;
    }
    if !tracked_object_fits(result as *const *mut libc::passwd) {
        return libc::EINVAL;
    }

    unsafe { *result = ptr::null_mut() };
    if !tracked_object_fits(pwd as *const libc::passwd) {
        return libc::EINVAL;
    }

    if !nss_module::is_files_only(&nss_module::services(Database::Passwd)) {
        return match next_passwd_entry() {
            Ok(entry) => {
                let rc = unsafe {
                    fill_passwd_r(&entry, pwd, buf, effective_buffer_len(buf, buflen), result)
                };
                if rc == libc::ERANGE {
                    // Hand the same entry back once the caller grows its buffer.
                    PW_PENDING.with(|p| *p.borrow_mut() = Some(entry));
                }
                rc
            }
            Err(err) => err.unwrap_or(libc::ENOENT),
        };
    }

    with_pwd_storage(|storage| {
        storage.refresh_cache();

        if (storage.entries.is_empty() && storage.iter_idx == 0)
            || storage.entries_generation != storage.cache_generation
        {
            storage.rebuild_entries();
        }

        if storage.iter_idx >= storage.entries.len() {
            if let Some(err) = storage.backend_io_error() {
                return err;
            }
            return libc::ENOENT;
        }

        let entry = storage.entries[storage.iter_idx].clone();
        let rc =
            unsafe { fill_passwd_r(&entry, pwd, buf, effective_buffer_len(buf, buflen), result) };
        if rc == 0 {
            storage.iter_idx += 1;
        }
        rc
    })
}

// ===========================================================================
// Shadow password database (<shadow.h>) — Implemented
// ===========================================================================
//
// Parses /etc/shadow for password aging/expiry metadata.
// Format: name:password:lastchg:min:max:warn:inact:expire:reserved

const SHADOW_PATH: &str = "/etc/shadow";

/// Parsed shadow entry stored in thread-local static storage.
#[repr(C)]
struct SpwdEntry {
    sp_namp: *mut c_char, // login name
    sp_pwdp: *mut c_char, // encrypted password
    sp_lstchg: i64,       // last password change (days since epoch)
    sp_min: i64,          // min days between changes
    sp_max: i64,          // max days between changes
    sp_warn: i64,         // warning days before expiry
    sp_inact: i64,        // inactive days after expiry
    sp_expire: i64,       // account expiration (days since epoch)
    sp_flag: u64,         // reserved
}

impl SpwdEntry {
    fn empty() -> Self {
        Self {
            sp_namp: ptr::null_mut(),
            sp_pwdp: ptr::null_mut(),
            sp_lstchg: -1,
            sp_min: -1,
            sp_max: -1,
            sp_warn: -1,
            sp_inact: -1,
            sp_expire: -1,
            sp_flag: 0,
        }
    }
}

struct ShadowTlsStorage {
    buf: Vec<u8>,
    entry: SpwdEntry,
    iter_idx: usize,
    cache: Vec<String>,
}

#[cfg(feature = "owned-tls-cache")]
// SAFETY: ShadowTlsStorage is accessed through OwnedTlsCache, which serializes
// access to each per-thread boxed value. The raw pointers stored in `entry`
// only point into the same boxed ShadowTlsStorage buffer and are refreshed
// before returning static shadow entries to callers.
unsafe impl Send for ShadowTlsStorage {}

impl ShadowTlsStorage {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            entry: SpwdEntry::empty(),
            iter_idx: 0,
            cache: Vec::new(),
        }
    }
}

#[cfg(feature = "owned-tls-cache")]
static SHADOW_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<ShadowTlsStorage> =
    crate::owned_tls_cache::OwnedTlsCache::new(ShadowTlsStorage::new);

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static SHADOW_TLS: RefCell<ShadowTlsStorage> = RefCell::new(ShadowTlsStorage::new());
}

fn with_shadow_storage<R>(callback: impl FnOnce(&mut ShadowTlsStorage) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        SHADOW_OWNED_TLS.with(callback)
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        SHADOW_TLS.with(|cell| {
            let mut storage = cell.borrow_mut();
            callback(&mut storage)
        })
    }
}

/// Pack the name+passwd from a parsed [`ShadowEntry`] into the
/// thread-local TLS buffer and copy the seven numeric fields into
/// the layout-stable SpwdEntry.
fn fill_shadow_parsed(
    parsed: &frankenlibc_core::pwd::shadow::ShadowEntry,
    buf: &mut Vec<u8>,
    entry: &mut SpwdEntry,
) {
    buf.clear();
    buf.extend_from_slice(&parsed.name);
    buf.push(0);
    let pass_offset = buf.len();
    buf.extend_from_slice(&parsed.passwd);
    buf.push(0);

    entry.sp_namp = buf.as_mut_ptr() as *mut c_char;
    entry.sp_pwdp = unsafe { buf.as_mut_ptr().add(pass_offset) as *mut c_char };
    entry.sp_lstchg = parsed.lstchg;
    entry.sp_min = parsed.min;
    entry.sp_max = parsed.max;
    entry.sp_warn = parsed.warn;
    entry.sp_inact = parsed.inact;
    entry.sp_expire = parsed.expire;
    entry.sp_flag = parsed.flag;
}

/// Pack the name+passwd from a parsed [`ShadowEntry`] into a
/// caller-supplied buffer and write the seven numeric fields into
/// `*sp`. Returns 0 on success, ERANGE if the buffer is too small.
///
/// # Safety
/// `sp` must be writable `SpwdEntry` storage and `buf` writable for `buflen` bytes.
unsafe fn fill_shadow_parsed_caller(
    parsed: &frankenlibc_core::pwd::shadow::ShadowEntry,
    sp: *mut SpwdEntry,
    buf: *mut c_char,
    buflen: usize,
) -> c_int {
    let needed = parsed.name.len() + 1 + parsed.passwd.len() + 1;
    if needed > buflen {
        return libc::ERANGE;
    }
    let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, buflen) };
    buf_slice[..parsed.name.len()].copy_from_slice(&parsed.name);
    buf_slice[parsed.name.len()] = 0;
    let pass_off = parsed.name.len() + 1;
    buf_slice[pass_off..pass_off + parsed.passwd.len()].copy_from_slice(&parsed.passwd);
    buf_slice[pass_off + parsed.passwd.len()] = 0;

    unsafe {
        (*sp).sp_namp = buf;
        (*sp).sp_pwdp = buf.add(pass_off);
        (*sp).sp_lstchg = parsed.lstchg;
        (*sp).sp_min = parsed.min;
        (*sp).sp_max = parsed.max;
        (*sp).sp_warn = parsed.warn;
        (*sp).sp_inact = parsed.inact;
        (*sp).sp_expire = parsed.expire;
        (*sp).sp_flag = parsed.flag;
    }
    0
}

/// `getspnam` — look up a shadow entry by login name.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getspnam(name: *const c_char) -> *mut c_void {
    if name.is_null() {
        return ptr::null_mut();
    }
    let Some(name_bytes) = (unsafe { bounded_cstr_bytes(name) }) else {
        return ptr::null_mut();
    };
    match shadow_answer(name_bytes) {
        Answer::Found(entry) => with_shadow_storage(|storage| {
            fill_shadow_parsed(&entry, &mut storage.buf, &mut storage.entry);
            &mut storage.entry as *mut SpwdEntry as *mut c_void
        }),
        Answer::NotFound => ptr::null_mut(),
        Answer::Unavailable(err) | Answer::TryAgain(err) => {
            unsafe { set_abi_errno(err) };
            ptr::null_mut()
        }
        Answer::BufferTooSmall => {
            unsafe { set_abi_errno(libc::ERANGE) };
            ptr::null_mut()
        }
    }
}

/// The files source of the shadow database: an unreadable /etc/shadow (the
/// usual case for unprivileged callers) is an unavailable source.
fn files_shadow_answer(name: &[u8]) -> Answer<frankenlibc_core::pwd::shadow::ShadowEntry> {
    match std::fs::read(SHADOW_PATH) {
        Ok(content) => match frankenlibc_core::pwd::shadow::lookup_shadow_by_name(&content, name) {
            Some(entry) => Answer::Found(entry),
            None => Answer::NotFound,
        },
        Err(err) => Answer::Unavailable(err.raw_os_error().unwrap_or(libc::EACCES)),
    }
}

/// The shadow entry for `name` from the sources nsswitch.conf's `shadow:`
/// line configures.
fn shadow_answer(name: &[u8]) -> Answer<frankenlibc_core::pwd::shadow::ShadowEntry> {
    frankenlibc_core::nss::lookup(
        &nss_module::services(Database::Shadow),
        |service| match service.kind() {
            SourceKind::Files => files_shadow_answer(name),
            SourceKind::Module => nss_module::getspnam(service.name(), name),
        },
        None,
    )
}

/// `getspnam_r` — reentrant shadow lookup by name.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getspnam_r(
    name: *const c_char,
    spbuf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if name.is_null() || spbuf.is_null() || buf.is_null() || result.is_null() {
        return libc::EINVAL;
    }
    if !tracked_object_fits(result as *const *mut c_void) {
        return libc::EINVAL;
    }

    unsafe { *result = ptr::null_mut() };
    if !tracked_object_fits(spbuf.cast::<SpwdEntry>()) {
        return libc::EINVAL;
    }

    let Some(name_bytes) = (unsafe { bounded_cstr_bytes(name) }) else {
        return libc::EINVAL;
    };

    match shadow_answer(name_bytes) {
        Answer::Found(entry) => {
            let rc = unsafe {
                fill_shadow_parsed_caller(
                    &entry,
                    spbuf as *mut SpwdEntry,
                    buf,
                    effective_buffer_len(buf, buflen),
                )
            };
            if rc == 0 {
                unsafe { *result = spbuf };
            }
            rc
        }
        // glibc: a miss is 0 with *result NULL, not ENOENT.
        Answer::NotFound => 0,
        Answer::Unavailable(err) | Answer::TryAgain(err) => err,
        Answer::BufferTooSmall => libc::ERANGE,
    }
}

/// `setspent` — rewind the shadow database iterator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn setspent() {
    reset_shadow_enumeration();
}

/// `endspent` — close the shadow database.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn endspent() {
    reset_shadow_enumeration();
    if !nss_module::is_files_only(&nss_module::services(Database::Shadow)) {
        nss_module::ent_end(EntDb::Shadow);
    }
    with_shadow_storage(|storage| {
        storage.iter_idx = 0;
        storage.cache.clear();
    });
}

impl ShadowTlsStorage {
    /// The next well-formed entry of the files source; `restart` takes a
    /// fresh snapshot of /etc/shadow. Malformed lines are skipped.
    fn next_files_entry(
        &mut self,
        restart: bool,
    ) -> Answer<frankenlibc_core::pwd::shadow::ShadowEntry> {
        if restart {
            self.iter_idx = 0;
            self.cache.clear();
            match std::fs::read_to_string(SHADOW_PATH) {
                Ok(content) => self.cache.extend(content.lines().map(str::to_owned)),
                Err(err) => return Answer::Unavailable(err.raw_os_error().unwrap_or(libc::EACCES)),
            }
        }
        while let Some(line) = self.cache.get(self.iter_idx) {
            self.iter_idx += 1;
            if let Some(entry) = frankenlibc_core::pwd::shadow::parse_shadow_line(line.as_bytes()) {
                return Answer::Found(entry);
            }
        }
        Answer::NotFound
    }
}

thread_local! {
    /// `getspent` position across the configured shadow sources, and an entry
    /// `getspent_r` could not fit into the caller's buffer.
    static SP_ENT: Cell<EntCursor> = const { Cell::new(EntCursor { source: 0, started: false }) };
    static SP_PENDING: RefCell<Option<frankenlibc_core::pwd::shadow::ShadowEntry>> =
        const { RefCell::new(None) };
}

/// Next shadow entry: `Err(None)` at the end, `Err(Some(errno))` when a
/// source failed and its action ends the walk. An enumeration starts
/// implicitly on the first call, as with glibc (no `setspent` required).
fn next_shadow_entry() -> Result<frankenlibc_core::pwd::shadow::ShadowEntry, Option<c_int>> {
    if let Some(entry) = SP_PENDING.with(|p| p.borrow_mut().take()) {
        return Ok(entry);
    }
    loop {
        let mut cursor = SP_ENT.with(Cell::get);
        let (step, service) =
            nss_module::ent_step(EntDb::Shadow, &mut cursor, nss_module::getspent);
        SP_ENT.with(|c| c.set(cursor));
        let answer = match step {
            EntStep::Done => return Err(None),
            EntStep::Files { restart } => with_shadow_storage(|s| s.next_files_entry(restart)),
            EntStep::Module(answer) => answer,
        };
        let (status, err) = match answer {
            Answer::Found(entry) => return Ok(entry),
            Answer::NotFound => (Status::NotFound, None),
            Answer::TryAgain(err) => (Status::TryAgain, Some(err)),
            Answer::Unavailable(err) => (Status::Unavailable, Some(err)),
            Answer::BufferTooSmall => (Status::Unavailable, Some(libc::ERANGE)),
        };
        let Some(service) = service else {
            return Err(None);
        };
        let mut cursor = SP_ENT.with(Cell::get);
        let advanced = nss_module::ent_advance(&mut cursor, &service, status);
        SP_ENT.with(|c| c.set(cursor));
        if !advanced {
            return Err(err);
        }
    }
}

fn reset_shadow_enumeration() {
    SP_ENT.with(|c| c.set(EntCursor::default()));
    SP_PENDING.with(|p| *p.borrow_mut() = None);
}

/// `getspent` — read the next shadow entry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getspent() -> *mut c_void {
    match next_shadow_entry() {
        Ok(entry) => with_shadow_storage(|storage| {
            fill_shadow_parsed(&entry, &mut storage.buf, &mut storage.entry);
            &mut storage.entry as *mut SpwdEntry as *mut c_void
        }),
        Err(err) => {
            if let Some(err) = err {
                unsafe { set_abi_errno(err) };
            }
            ptr::null_mut()
        }
    }
}

/// `getspent_r` — reentrant version of getspent.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getspent_r(
    spbuf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if spbuf.is_null() || buf.is_null() || result.is_null() {
        return libc::EINVAL;
    }
    if !tracked_object_fits(result as *const *mut c_void) {
        return libc::EINVAL;
    }

    unsafe { *result = ptr::null_mut() };
    if !tracked_object_fits(spbuf.cast::<SpwdEntry>()) {
        return libc::EINVAL;
    }

    match next_shadow_entry() {
        Ok(entry) => {
            let rc = unsafe {
                fill_shadow_parsed_caller(
                    &entry,
                    spbuf as *mut SpwdEntry,
                    buf,
                    effective_buffer_len(buf, buflen),
                )
            };
            if rc == libc::ERANGE {
                // Hand the same entry back once the caller grows its buffer.
                SP_PENDING.with(|p| *p.borrow_mut() = Some(entry));
            } else if rc == 0 {
                unsafe { *result = spbuf };
            }
            rc
        }
        Err(err) => err.unwrap_or(libc::ENOENT),
    }
}

// ===========================================================================
// gshadow database — /etc/gshadow
// ===========================================================================
// ---------------------------------------------------------------------------
// gshadow database (bd-kcbm)
// ---------------------------------------------------------------------------
//
// The gshadow database stores group passwords and admin lists.
// Format: groupname:password:admins:members
// struct sgrp { sg_namp, sg_passwd, *sg_adm, *sg_mem } (glibc)
//
// Implementation reads /etc/gshadow using the core parser from
// frankenlibc_core::pwd::gshadow.

use frankenlibc_core::pwd::gshadow::{
    Gshadow, lookup_gshadow_by_name, parse_gshadow_file_line, parse_gshadow_line,
};

/// C-compatible struct sgrp layout (matches glibc <gshadow.h>).
#[repr(C)]
struct Sgrp {
    sg_namp: *mut c_char,
    sg_passwd: *mut c_char,
    sg_adm: *mut *mut c_char,
    sg_mem: *mut *mut c_char,
}

/// Thread-local buffer for non-reentrant gshadow functions.
/// Stores the sgrp struct + all strings + pointer arrays.
const GSHADOW_BUF_SIZE: usize = 4096;

struct GshadowTlsStorage {
    buf: Vec<u8>,
    enum_offset: usize,
}

impl GshadowTlsStorage {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            enum_offset: 0,
        }
    }
}

#[cfg(feature = "owned-tls-cache")]
static GSHADOW_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<GshadowTlsStorage> =
    crate::owned_tls_cache::OwnedTlsCache::new(GshadowTlsStorage::new);

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static GSHADOW_TLS: RefCell<GshadowTlsStorage> = RefCell::new(GshadowTlsStorage::new());
}

fn with_gshadow_storage<R>(callback: impl FnOnce(&mut GshadowTlsStorage) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        GSHADOW_OWNED_TLS.with(callback)
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        GSHADOW_TLS.with(|cell| {
            let mut storage = cell.borrow_mut();
            callback(&mut storage)
        })
    }
}

/// Read configured gshadow content. Returns None if the file doesn't exist.
const GSHADOW_PATH: &str = "/etc/gshadow";
const GSHADOW_PATH_ENV: &str = "FRANKENLIBC_GSHADOW_PATH";

fn read_gshadow_file() -> Option<Vec<u8>> {
    let path = std::env::var_os(GSHADOW_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(GSHADOW_PATH));
    std::fs::read(path).ok()
}

/// Pack a Gshadow entry into a buffer, returning a pointer to the sgrp struct.
/// Returns null if the buffer is too small.
///
/// Buffer layout: [Sgrp] [name\0] [passwd\0] [adm_ptrs... NULL] [mem_ptrs... NULL] [adm_strs\0...] [mem_strs\0...]
unsafe fn pack_gshadow_into_buf(entry: &Gshadow, buf: *mut u8, buflen: usize) -> *mut Sgrp {
    // Align the struct to pointer alignment (8 bytes on x86_64).
    let align = core::mem::align_of::<Sgrp>();
    let buf_addr = buf as usize;
    let align_offset = buf_addr.wrapping_neg() & (align - 1);
    if align_offset >= buflen {
        return ptr::null_mut();
    }
    let aligned_buf = unsafe { buf.add(align_offset) };
    let effective_buflen = buflen - align_offset;

    let sgrp_size = core::mem::size_of::<Sgrp>();

    // Split comma-separated lists, dropping empty tokens — glibc never yields an
    // empty admin/member name, so trailing/leading/doubled commas collapse away.
    let adm_list: Vec<&[u8]> = entry
        .sg_adm
        .split(|&b| b == b',')
        .filter(|m| !m.is_empty())
        .collect();
    let mem_list: Vec<&[u8]> = entry
        .sg_mem
        .split(|&b| b == b',')
        .filter(|m| !m.is_empty())
        .collect();

    // Calculate total space needed.
    // Pointer arrays need alignment, so account for worst-case padding.
    let ptr_align = core::mem::align_of::<*mut c_char>();
    let name_len = entry.sg_namp.len() + 1;
    let passwd_len = entry.sg_passwd.len() + 1;
    let adm_ptrs_size = (adm_list.len() + 1) * core::mem::size_of::<*mut c_char>();
    let mem_ptrs_size = (mem_list.len() + 1) * core::mem::size_of::<*mut c_char>();
    let adm_strs_size: usize = adm_list.iter().map(|s| s.len() + 1).sum();
    let mem_strs_size: usize = mem_list.iter().map(|s| s.len() + 1).sum();
    // Add worst-case alignment padding (ptr_align - 1 bytes) before each pointer array
    let total = sgrp_size
        + name_len
        + passwd_len
        + (ptr_align - 1) // padding before admin pointer array
        + adm_ptrs_size
        + adm_strs_size
        + (ptr_align - 1) // padding before member pointer array
        + mem_ptrs_size
        + mem_strs_size;

    if total > effective_buflen {
        return ptr::null_mut();
    }

    let sgrp = aligned_buf as *mut Sgrp;
    let mut cursor = unsafe { aligned_buf.add(sgrp_size) };

    // Write name string.
    let name_ptr = cursor as *mut c_char;
    unsafe {
        ptr::copy_nonoverlapping(entry.sg_namp.as_ptr(), cursor, entry.sg_namp.len());
        *cursor.add(entry.sg_namp.len()) = 0;
        cursor = cursor.add(name_len);
    }

    // Write passwd string.
    let passwd_ptr = cursor as *mut c_char;
    unsafe {
        ptr::copy_nonoverlapping(entry.sg_passwd.as_ptr(), cursor, entry.sg_passwd.len());
        *cursor.add(entry.sg_passwd.len()) = 0;
        cursor = cursor.add(passwd_len);
    }

    // Align cursor for pointer arrays.
    let cursor_addr = cursor as usize;
    let ptr_align_padding = cursor_addr.wrapping_neg() & (ptr_align - 1);
    cursor = unsafe { cursor.add(ptr_align_padding) };

    // Write admin pointer array.
    let adm_ptrs = cursor as *mut *mut c_char;
    unsafe { cursor = cursor.add(adm_ptrs_size) };
    // Write admin strings and fill pointers.
    for (i, adm) in adm_list.iter().enumerate() {
        unsafe {
            *(adm_ptrs.add(i)) = cursor as *mut c_char;
            ptr::copy_nonoverlapping(adm.as_ptr(), cursor, adm.len());
            *cursor.add(adm.len()) = 0;
            cursor = cursor.add(adm.len() + 1);
        }
    }
    unsafe { *(adm_ptrs.add(adm_list.len())) = ptr::null_mut() };

    // Align cursor for member pointer array.
    let cursor_addr = cursor as usize;
    let ptr_align_padding = cursor_addr.wrapping_neg() & (ptr_align - 1);
    cursor = unsafe { cursor.add(ptr_align_padding) };

    // Write member pointer array.
    let mem_ptrs = cursor as *mut *mut c_char;
    unsafe { cursor = cursor.add(mem_ptrs_size) };
    for (i, mem) in mem_list.iter().enumerate() {
        unsafe {
            *(mem_ptrs.add(i)) = cursor as *mut c_char;
            ptr::copy_nonoverlapping(mem.as_ptr(), cursor, mem.len());
            *cursor.add(mem.len()) = 0;
            cursor = cursor.add(mem.len() + 1);
        }
    }
    unsafe { *(mem_ptrs.add(mem_list.len())) = ptr::null_mut() };

    // Fill sgrp struct.
    unsafe {
        (*sgrp).sg_namp = name_ptr;
        (*sgrp).sg_passwd = passwd_ptr;
        (*sgrp).sg_adm = adm_ptrs;
        (*sgrp).sg_mem = mem_ptrs;
    }

    sgrp
}

/// Pack into thread-local buffer and return pointer (for non-_r functions).
fn gshadow_to_static_sgrp(entry: &Gshadow) -> *mut c_void {
    with_gshadow_storage(|storage| pack_gshadow_into_static_storage(storage, entry))
}

fn pack_gshadow_into_static_storage(
    storage: &mut GshadowTlsStorage,
    entry: &Gshadow,
) -> *mut c_void {
    storage.buf.resize(GSHADOW_BUF_SIZE, 0);
    let ptr = unsafe { pack_gshadow_into_buf(entry, storage.buf.as_mut_ptr(), GSHADOW_BUF_SIZE) };
    ptr as *mut c_void
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setsgent() {
    with_gshadow_storage(|storage| storage.enum_offset = 0);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endsgent() {
    with_gshadow_storage(|storage| storage.enum_offset = 0);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsgent() -> *mut c_void {
    let content = match read_gshadow_file() {
        Some(c) => c,
        None => return ptr::null_mut(),
    };
    with_gshadow_storage(|storage| {
        let remaining = if storage.enum_offset < content.len() {
            &content[storage.enum_offset..]
        } else {
            return ptr::null_mut();
        };
        for line in remaining.split(|&b| b == b'\n') {
            storage.enum_offset += line.len() + 1; // +1 for the newline
            // FILE rule: comments/blanks skipped, leading blanks stripped.
            if let Some(entry) = parse_gshadow_file_line(line) {
                return pack_gshadow_into_static_storage(storage, &entry);
            }
        }
        ptr::null_mut()
    })
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsgent_r(
    _result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = ptr::null_mut() };
    }
    let content = match read_gshadow_file() {
        Some(c) => c,
        None => return libc::ENOENT,
    };
    with_gshadow_storage(|storage| {
        let remaining = if storage.enum_offset < content.len() {
            &content[storage.enum_offset..]
        } else {
            return libc::ENOENT;
        };
        for line in remaining.split(|&b| b == b'\n') {
            storage.enum_offset += line.len() + 1;
            // FILE rule, same as the non-reentrant scanner above.
            if let Some(entry) = parse_gshadow_file_line(line) {
                let sgrp = unsafe { pack_gshadow_into_buf(&entry, buffer as *mut u8, buflen) };
                if sgrp.is_null() {
                    return libc::ERANGE;
                }
                if !result.is_null() {
                    unsafe { *result = sgrp as *mut c_void };
                }
                return 0;
            }
        }
        libc::ENOENT
    })
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsgnam(name: *const c_char) -> *mut c_void {
    if name.is_null() {
        return ptr::null_mut();
    }
    let Some(name_bytes) = (unsafe { bounded_cstr_bytes(name) }) else {
        return ptr::null_mut();
    };
    let content = match read_gshadow_file() {
        Some(c) => c,
        None => return ptr::null_mut(),
    };
    match lookup_gshadow_by_name(&content, name_bytes) {
        Some(entry) => gshadow_to_static_sgrp(&entry),
        None => ptr::null_mut(),
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsgnam_r(
    name: *const c_char,
    _result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = ptr::null_mut() };
    }
    if name.is_null() {
        return libc::EINVAL;
    }
    let Some(name_bytes) = (unsafe { bounded_cstr_bytes(name) }) else {
        return libc::EINVAL;
    };
    let content = match read_gshadow_file() {
        Some(c) => c,
        None => return libc::ENOENT,
    };
    match lookup_gshadow_by_name(&content, name_bytes) {
        Some(entry) => {
            let sgrp = unsafe { pack_gshadow_into_buf(&entry, buffer as *mut u8, buflen) };
            if sgrp.is_null() {
                return libc::ERANGE;
            }
            if !result.is_null() {
                unsafe { *result = sgrp as *mut c_void };
            }
            0
        }
        None => libc::ENOENT,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetsgent(_stream: *mut c_void) -> *mut c_void {
    // fgetsgent reads a single gshadow line from a FILE* stream.
    // Since we don't have a way to safely read a line from an arbitrary
    // FILE* in the interpose model, return null (not found).
    ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetsgent_r(
    _stream: *mut c_void,
    _result_buf: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = ptr::null_mut() };
    }
    libc::ENOENT
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sgetsgent(string: *const c_char) -> *mut c_void {
    if string.is_null() {
        return ptr::null_mut();
    }
    let Some(line_bytes) = (unsafe { bounded_cstr_bytes(string) }) else {
        return ptr::null_mut();
    };
    match parse_gshadow_line(line_bytes) {
        Some(entry) => gshadow_to_static_sgrp(&entry),
        None => ptr::null_mut(),
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sgetsgent_r(
    string: *const c_char,
    _result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = ptr::null_mut() };
    }
    if string.is_null() {
        return libc::EINVAL;
    }
    let Some(line_bytes) = (unsafe { bounded_cstr_bytes(string) }) else {
        return libc::EINVAL;
    };
    match parse_gshadow_line(line_bytes) {
        Some(entry) => {
            let sgrp = unsafe { pack_gshadow_into_buf(&entry, buffer as *mut u8, buflen) };
            if sgrp.is_null() {
                return libc::ERANGE;
            }
            if !result.is_null() {
                unsafe { *result = sgrp as *mut c_void };
            }
            0
        }
        None => libc::ENOENT,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putsgent(sgrp: *const c_void, stream: *mut c_void) -> c_int {
    if sgrp.is_null() || stream.is_null() {
        return -1;
    }
    // struct sgrp { char *sg_namp; char *sg_passwd; char **sg_adm; char **sg_mem; }.
    // glibc renders a NULL string field as an empty field (verified against the
    // host: a NULL sg_passwd yields "name::adm:mem") and comma-joins the admin /
    // member name lists.
    const SLOT_SCAN_CAP: usize = 1 << 20;
    let base = sgrp as *const *const c_char;
    let namp = unsafe { *base };
    let passwd = unsafe { *base.add(1) };
    let adm = unsafe { *base.add(2) as *const *const c_char };
    let mem = unsafe { *base.add(3) as *const *const c_char };

    let mut line: Vec<u8> = Vec::with_capacity(64);
    // Append a single string field (NULL -> empty); returns false on a malformed
    // (unterminated) string so the caller can report EINVAL.
    let push_field = |line: &mut Vec<u8>, p: *const c_char| -> bool {
        if p.is_null() {
            return true;
        }
        match unsafe { bounded_cstr_bytes(p) } {
            Some(b) => {
                line.extend_from_slice(b);
                true
            }
            None => false,
        }
    };
    // Append a comma-joined NULL-terminated name list (NULL list -> empty).
    let push_list = |line: &mut Vec<u8>, mut lp: *const *const c_char| -> bool {
        if lp.is_null() {
            return true;
        }
        let slots = known_remaining(lp as usize)
            .map_or(SLOT_SCAN_CAP, |r| r / std::mem::size_of::<*const c_char>());
        for i in 0..slots {
            let entry = unsafe { *lp };
            if entry.is_null() {
                return true;
            }
            match unsafe { bounded_cstr_bytes(entry) } {
                Some(b) => {
                    if i > 0 {
                        line.push(b',');
                    }
                    line.extend_from_slice(b);
                }
                None => return false,
            }
            lp = unsafe { lp.add(1) };
        }
        false // never reached the NULL terminator within the scan bound
    };

    if !push_field(&mut line, namp) {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    line.push(b':');
    if !push_field(&mut line, passwd) {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    line.push(b':');
    if !push_list(&mut line, adm) {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    line.push(b':');
    if !push_list(&mut line, mem) {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    line.push(b'\n');

    let written = unsafe { crate::stdio_abi::fwrite(line.as_ptr().cast(), 1, line.len(), stream) };
    if written == line.len() { 0 } else { -1 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lckpwdf() -> c_int {
    // Lock the password file — no-op in our implementation
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ulckpwdf() -> c_int {
    // Unlock the password file — no-op
    0
}

// ---------------------------------------------------------------------------
// uid_from_user / user_from_uid (BSD libutil pwcache)
// ---------------------------------------------------------------------------
//
// BSD libutil "lookup or report" interface used by find(1), ls(1), du(1).
// Thin wrappers over getpwnam/getpwuid; user_from_uid uses process-static
// storage so callers can pass the returned pointer through printf without
// copying.

/// BSD `uid_from_user(name, uid)` — look up the uid for `name` and
/// store it through `*uid`. Returns 0 on success, -1 if `name` is
/// NULL or no matching user exists.
///
/// # Safety
///
/// `name` must be a valid NUL-terminated C string or NULL. `uid`,
/// when non-NULL, must point to writable `uid_t` storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn uid_from_user(name: *const c_char, uid: *mut libc::uid_t) -> c_int {
    if name.is_null() {
        return -1;
    }
    // SAFETY: caller-supplied C string.
    let pw = unsafe { getpwnam(name) };
    if pw.is_null() {
        return -1;
    }
    if !uid.is_null() {
        // SAFETY: pw is a valid passwd struct returned by our getpwnam,
        // which uses process-static storage.
        unsafe { *uid = (*pw).pw_uid };
    }
    0
}

/// BSD `user_from_uid(uid, nouser)` — return a pointer to a static
/// C string with the username matching `uid`. If no user matches:
/// * with `nouser == 0`, returns NULL;
/// * with `nouser != 0`, formats `uid` as decimal ASCII into a
///   process-static buffer and returns its pointer.
///
/// The returned pointer is owned by the runtime and remains valid
/// until the next call to `user_from_uid` from any thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn user_from_uid(uid: libc::uid_t, nouser: c_int) -> *const c_char {
    use std::sync::Mutex;
    static FALLBACK: Mutex<[u8; 24]> = Mutex::new([0; 24]);

    // SAFETY: getpwuid returns either NULL or a passwd in process-
    // static storage owned by our pwd_abi machinery.
    let pw = unsafe { getpwuid(uid) };
    if !pw.is_null() {
        // SAFETY: pw_name is a valid C string in the same static storage.
        let name = unsafe { (*pw).pw_name };
        if !name.is_null() {
            return name as *const c_char;
        }
    }
    if nouser == 0 {
        return std::ptr::null();
    }

    // Render `uid` into the fallback buffer as decimal ASCII + NUL.
    let mut guard = FALLBACK.lock().unwrap_or_else(|p| p.into_inner());
    let buf: &mut [u8; 24] = &mut guard;
    let mut tmp = [0u8; 23];
    let mut len = 0usize;
    let mut v = uid as u64;
    if v == 0 {
        tmp[0] = b'0';
        len = 1;
    } else {
        while v > 0 {
            tmp[len] = b'0' + (v % 10) as u8;
            len += 1;
            v /= 10;
        }
    }
    for i in 0..len {
        buf[i] = tmp[len - 1 - i];
    }
    buf[len] = 0;
    let ptr = buf.as_ptr() as *const c_char;
    drop(guard);
    ptr
}

// Unit tests for this module are in tests/pwd_abi_test.rs.
// This module is compiled with #[cfg(not(test))] in lib.rs, so internal
// tests here would never run. The integration tests cover the public API.
