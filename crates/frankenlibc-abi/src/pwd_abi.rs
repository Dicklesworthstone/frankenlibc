//! ABI layer for `<pwd.h>` functions.
//!
//! Implements `getpwnam`, `getpwuid`, `getpwent`, `setpwent`, `endpwent`
//! using a files backend (parsing `/etc/passwd`).
//!
//! Returns pointers to thread-local static storage, matching glibc behavior
//! where each call overwrites the previous result.

use std::cell::{Cell, RefCell};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::UNIX_EPOCH;

use frankenlibc_core::errno;
use frankenlibc_core::nss::{Answer, Database, Service, SourceKind, Status};
use frankenlibc_core::syscall as raw_syscall;
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
    if entry.nis_compat_null_fields {
        return entry.pw_name.len().checked_add(1);
    }
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
    /// Physical line ends corresponding to `entries`, including skipped lines
    /// before each record. Reentrant files enumeration sizes the source line,
    /// not only the packed string fields.
    entry_line_ends: Vec<usize>,
    /// Parse accounting from the most recent `entries` build.
    #[allow(dead_code)]
    last_parse_stats: frankenlibc_core::pwd::ParseStats,
    /// Current iteration index for getpwent.
    iter_idx: usize,
    /// Successfully skipped physical lines within the current entry/EOF span.
    iter_scan_offset: usize,
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
            entry_line_ends: Vec::new(),
            last_parse_stats: frankenlibc_core::pwd::ParseStats::default(),
            iter_idx: 0,
            iter_scan_offset: 0,
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
        self.entry_line_ends.clear();
        self.clear_lookup_cache();
        self.iter_idx = 0;
        self.iter_scan_offset = 0;
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
                    self.entry_line_ends.clear();
                    self.clear_lookup_cache();
                    self.iter_idx = 0;
                    self.iter_scan_offset = 0;
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
                self.entry_line_ends.clear();
                self.clear_lookup_cache();
                self.iter_idx = 0;
                self.iter_scan_offset = 0;
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
        let mut end = 0;
        let entry_line_ends = self
            .current_content()
            .split_inclusive(|&byte| byte == b'\n')
            .filter_map(|line| {
                end += line.len();
                frankenlibc_core::pwd::parse_passwd_line(line).map(|_| end)
            })
            .collect();
        self.entries = entries;
        self.entry_line_ends = entry_line_ends;
        self.last_parse_stats = stats;
        self.iter_idx = 0;
        self.iter_scan_offset = 0;
        self.entries_generation = self.cache_generation;
    }

    fn enumeration_exceeds_buffer(&mut self, buflen: usize) -> bool {
        let content = self.current_content();
        let start = self
            .iter_idx
            .checked_sub(1)
            .and_then(|idx| self.entry_line_ends.get(idx))
            .copied()
            .unwrap_or(0)
            .max(self.iter_scan_offset);
        let entry_end = self.entry_line_ends.get(self.iter_idx).copied();
        let end = entry_end.unwrap_or(content.len());
        let mut consumed = start;
        let mut too_small = false;
        for line in content[start..end].split_inclusive(|&byte| byte == b'\n') {
            if frankenlibc_core::pwd::files_lookup_exceeds_buffer(line, buflen, |_| false) {
                too_small = true;
                break;
            }
            // Retain the actual record until its caller-buffer copy succeeds.
            // Skipped comments/invalid lines and an observed EOF stay consumed
            // when a caller retries later using a smaller buffer.
            if Some(consumed + line.len()) == entry_end {
                break;
            }
            consumed += line.len();
        }
        self.iter_scan_offset = consumed;
        too_small
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
    let _ = files_setpwent();
}

/// Rewind only the native files source, without invoking NSS modules.
pub(crate) fn files_setpwent() -> c_int {
    with_pwd_storage(|storage| {
        storage.refresh_cache();
        storage.rebuild_entries();
        storage.backend_io_error().unwrap_or(0)
    })
}

/// POSIX `endpwent` — close the passwd enumeration and free cached data.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endpwent() {
    reset_passwd_enumeration();
    if !nss_module::is_files_only(&nss_module::services(Database::Passwd)) {
        nss_module::ent_end(EntDb::Passwd);
    }
    files_endpwent();
}

/// Release only the files source's snapshot and enumeration state.
pub(crate) fn files_endpwent() {
    with_pwd_storage(|storage| {
        if storage.file_cache.is_some() || !storage.entries.is_empty() {
            storage.cache_metrics.invalidations += 1;
        }
        storage.entries.clear();
        storage.entry_line_ends.clear();
        storage.clear_lookup_cache();
        storage.iter_idx = 0;
        storage.iter_scan_offset = 0;
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
    // SAFETY: forward the public reentrant lookup contract.
    unsafe { getpwnam_r_impl(name, pwd, buf, buflen, result, false) }
}

/// Files-module lookup: never re-enter the configured NSS service chain.
pub(crate) unsafe fn files_getpwnam_r(
    name: *const c_char,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::passwd,
) -> c_int {
    // SAFETY: caller supplies the same buffers as getpwnam_r.
    unsafe { getpwnam_r_impl(name, pwd, buf, buflen, result, true) }
}

unsafe fn getpwnam_r_impl(
    name: *const c_char,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::passwd,
    files_only: bool,
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
    let key = PwKey::Name(name_bytes);
    let capacity = Some(effective_buffer_len(buf, buflen));
    let answer = if files_only {
        files_passwd_answer(key, capacity)
    } else {
        passwd_answer(key, capacity)
    };
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
    // SAFETY: forward the public reentrant lookup contract.
    unsafe { getpwuid_r_impl(uid, pwd, buf, buflen, result, false) }
}

/// Files-module lookup by uid, independent of nsswitch.conf.
pub(crate) unsafe fn files_getpwuid_r(
    uid: libc::uid_t,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::passwd,
) -> c_int {
    // SAFETY: caller supplies the same buffers as getpwuid_r.
    unsafe { getpwuid_r_impl(uid, pwd, buf, buflen, result, true) }
}

unsafe fn getpwuid_r_impl(
    uid: libc::uid_t,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::passwd,
    files_only: bool,
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

    let capacity = Some(effective_buffer_len(buf, buflen));
    let answer = if files_only {
        files_passwd_answer(PwKey::Uid(uid), capacity)
    } else {
        passwd_answer(PwKey::Uid(uid), capacity)
    };
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
pub(crate) unsafe fn fill_passwd_r(
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

    if entry.nis_compat_null_fields {
        // SAFETY: `needed` covers the name and terminator; the remaining
        // fields of a colon-less NIS directive are null by the GNU contract.
        unsafe {
            ptr::copy_nonoverlapping(
                entry.pw_name.as_ptr().cast::<c_char>(),
                buf,
                entry.pw_name.len(),
            );
            *buf.add(entry.pw_name.len()) = 0;
            *pwd = libc::passwd {
                pw_name: buf,
                pw_passwd: ptr::null_mut(),
                pw_uid: entry.pw_uid,
                pw_gid: entry.pw_gid,
                pw_gecos: ptr::null_mut(),
                pw_dir: ptr::null_mut(),
                pw_shell: ptr::null_mut(),
            };
            *result = pwd;
        }
        return 0;
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
    // SAFETY: forward the public reentrant enumeration contract.
    unsafe { getpwent_r_impl(pwd, buf, buflen, result, false) }
}

/// Enumerate the files source without consulting other NSS services.
/// EOF is a successful null result; real backend errors retain their errno.
pub(crate) unsafe fn files_getpwent_r(
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::passwd,
) -> c_int {
    // SAFETY: caller supplies the same buffers as getpwent_r.
    unsafe { getpwent_r_impl(pwd, buf, buflen, result, true) }
}

unsafe fn getpwent_r_impl(
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::passwd,
    files_only: bool,
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

    if !files_only && !nss_module::is_files_only(&nss_module::services(Database::Passwd)) {
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

        if storage.entries_generation != storage.cache_generation {
            storage.rebuild_entries();
        }

        if storage.enumeration_exceeds_buffer(effective_buffer_len(buf, buflen)) {
            return libc::ERANGE;
        }

        if storage.iter_idx >= storage.entries.len() {
            if let Some(err) = storage.backend_io_error() {
                return err;
            }
            return if files_only { 0 } else { libc::ENOENT };
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

fn read_shadow_file() -> std::io::Result<Vec<u8>> {
    // SAFETY: the key is static and NUL-terminated. secure_getenv ignores the
    // fixture/backend override in a privileged execution context.
    let configured =
        unsafe { crate::stdlib_abi::secure_getenv(c"FRANKENLIBC_SHADOW_PATH".as_ptr()) };
    let path = if configured.is_null() {
        PathBuf::from(SHADOW_PATH)
    } else {
        // SAFETY: secure_getenv returns a NUL-terminated environment value.
        let bytes = unsafe { std::ffi::CStr::from_ptr(configured) }.to_bytes();
        if bytes.is_empty() {
            PathBuf::from(SHADOW_PATH)
        } else {
            PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
        }
    };
    std::fs::read(path)
}

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
    cache: Vec<u8>,
    files_loaded: bool,
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
            files_loaded: false,
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
    match shadow_answer(name_bytes, None) {
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
fn files_shadow_answer(
    name: &[u8],
    capacity: Option<usize>,
) -> Answer<frankenlibc_core::pwd::shadow::ShadowEntry> {
    let content = match read_shadow_file() {
        Ok(content) => content,
        Err(err) => return Answer::Unavailable(err.raw_os_error().unwrap_or(libc::EACCES)),
    };
    if capacity.is_some_and(|len| len < 3) {
        return Answer::BufferTooSmall;
    }
    for line in content.split_inclusive(|&byte| byte == b'\n') {
        // The files reader must fit every scanned physical line, including
        // comments and malformed entries, before it can test the login name.
        if capacity.is_some_and(|len| line.len().saturating_add(2) > len) {
            return Answer::BufferTooSmall;
        }
        if let Some(entry) = frankenlibc_core::pwd::shadow::parse_shadow_line(line)
            && entry.name == name
        {
            return Answer::Found(entry);
        }
    }
    Answer::NotFound
}

/// The shadow entry for `name` from the sources nsswitch.conf's `shadow:`
/// line configures.
fn shadow_answer(
    name: &[u8],
    capacity: Option<usize>,
) -> Answer<frankenlibc_core::pwd::shadow::ShadowEntry> {
    frankenlibc_core::nss::lookup(
        &nss_module::services(Database::Shadow),
        |service| match service.kind() {
            SourceKind::Files => files_shadow_answer(name, capacity),
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
    // SAFETY: forward the public reentrant lookup contract.
    unsafe { getspnam_r_impl(name, spbuf, buf, buflen, result, false) }
}

/// Files-module lookup, independent of the configured NSS service chain.
pub(crate) unsafe fn files_getspnam_r(
    name: *const c_char,
    spbuf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    // SAFETY: the NSS caller supplies the same storage as getspnam_r.
    unsafe { getspnam_r_impl(name, spbuf, buf, buflen, result, true) }
}

unsafe fn getspnam_r_impl(
    name: *const c_char,
    spbuf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
    files_only: bool,
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

    let capacity = effective_buffer_len(buf, buflen);
    let answer = if files_only {
        files_shadow_answer(name_bytes, Some(capacity))
    } else {
        shadow_answer(name_bytes, Some(capacity))
    };
    match answer {
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
    files_endspent();
}

/// Rewind only the native files source and report an unreadable backend.
pub(crate) fn files_setspent() -> c_int {
    with_shadow_storage(|storage| storage.load_files().err().unwrap_or(0))
}

/// Release only the files cursor, without invoking installed NSS modules.
pub(crate) fn files_endspent() {
    with_shadow_storage(|storage| {
        storage.iter_idx = 0;
        storage.cache.clear();
        storage.files_loaded = false;
    });
}

impl ShadowTlsStorage {
    fn load_files(&mut self) -> Result<(), c_int> {
        self.iter_idx = 0;
        self.cache.clear();
        self.files_loaded = false;
        self.cache =
            read_shadow_file().map_err(|err| err.raw_os_error().unwrap_or(libc::EACCES))?;
        self.files_loaded = true;
        Ok(())
    }

    /// Read byte-oriented records so non-UTF-8 account data stays intact.
    /// A short caller buffer leaves the current physical line unconsumed.
    fn next_files_entry(
        &mut self,
        restart: bool,
        capacity: Option<usize>,
    ) -> Answer<frankenlibc_core::pwd::shadow::ShadowEntry> {
        if (restart || !self.files_loaded)
            && let Err(err) = self.load_files()
        {
            return Answer::Unavailable(err);
        }
        if capacity.is_some_and(|len| len < 3) {
            return Answer::BufferTooSmall;
        }
        while self.iter_idx < self.cache.len() {
            let remaining = &self.cache[self.iter_idx..];
            let len = remaining
                .iter()
                .position(|&byte| byte == b'\n')
                .map_or(remaining.len(), |offset| offset + 1);
            let line = &remaining[..len];
            if capacity.is_some_and(|available| len.saturating_add(2) > available) {
                return Answer::BufferTooSmall;
            }
            self.iter_idx += len;
            if let Some(entry) = frankenlibc_core::pwd::shadow::parse_shadow_line(line) {
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
            EntStep::Files { restart } => {
                with_shadow_storage(|s| s.next_files_entry(restart, None))
            }
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
    // SAFETY: forward the public reentrant enumeration contract.
    unsafe { getspent_r_impl(spbuf, buf, buflen, result, false) }
}

/// Enumerate only the files source. EOF is a successful null result.
pub(crate) unsafe fn files_getspent_r(
    spbuf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    // SAFETY: the NSS caller supplies the same storage as getspent_r.
    unsafe { getspent_r_impl(spbuf, buf, buflen, result, true) }
}

unsafe fn getspent_r_impl(
    spbuf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
    files_only: bool,
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

    let capacity = effective_buffer_len(buf, buflen);
    if files_only {
        return with_shadow_storage(|storage| {
            match storage.next_files_entry(false, Some(capacity)) {
                Answer::Found(entry) => {
                    // The physical-line bound also covers both packed strings.
                    // SAFETY: output alignment and tracked extents were checked above.
                    let rc =
                        unsafe { fill_shadow_parsed_caller(&entry, spbuf.cast(), buf, capacity) };
                    if rc == 0 {
                        // SAFETY: result is checked writable caller storage.
                        unsafe { *result = spbuf };
                    }
                    rc
                }
                Answer::NotFound => 0,
                Answer::Unavailable(err) | Answer::TryAgain(err) => err,
                Answer::BufferTooSmall => libc::ERANGE,
            }
        });
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

use frankenlibc_core::pwd::gshadow::{Gshadow, parse_gshadow_file_line, parse_gshadow_line};

/// C-compatible struct sgrp layout (matches glibc <gshadow.h>).
#[repr(C)]
struct Sgrp {
    sg_namp: *mut c_char,
    sg_passwd: *mut c_char,
    sg_adm: *mut *mut c_char,
    sg_mem: *mut *mut c_char,
}

struct GshadowRecord {
    entry: Gshadow,
    input_len: usize,
}

/// Thread-local answer storage and an independently owned files cursor.
/// Reentrant results never borrow this scratch storage.
struct GshadowTlsStorage {
    buf: Vec<u8>,
    entry: Sgrp,
    reader: Option<std::io::BufReader<std::fs::File>>,
    line: Vec<u8>,
    pending: Option<GshadowRecord>,
    line_pending: bool,
}

impl GshadowTlsStorage {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            entry: Sgrp {
                sg_namp: ptr::null_mut(),
                sg_passwd: ptr::null_mut(),
                sg_adm: ptr::null_mut(),
                sg_mem: ptr::null_mut(),
            },
            reader: None,
            line: Vec::new(),
            pending: None,
            line_pending: false,
        }
    }

    fn open_files(&mut self) -> Result<(), c_int> {
        if self.reader.is_none() {
            let file = std::fs::File::open(gshadow_source_path())
                .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
            self.reader = Some(std::io::BufReader::new(file));
        }
        Ok(())
    }

    fn close_files(&mut self) {
        self.reader = None;
        self.line.clear();
        self.pending = None;
        self.line_pending = false;
    }

    fn next_files_entry(
        &mut self,
        capacity: Option<usize>,
    ) -> Result<Option<GshadowRecord>, c_int> {
        use std::io::BufRead;

        if let Some(entry) = self.pending.take() {
            return Ok(Some(entry));
        }
        self.open_files()?;
        if capacity.is_some_and(|capacity| capacity < 3) {
            return Err(libc::ERANGE);
        }
        loop {
            if !self.line_pending {
                self.line.clear();
                let count = self
                    .reader
                    .as_mut()
                    .ok_or(libc::EIO)?
                    .read_until(b'\n', &mut self.line)
                    .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
                if count == 0 {
                    return Ok(None);
                }
                self.line_pending = true;
            }
            // GNU checks physical line capacity before skipping a comment or
            // malformed row. Keep that row for a larger-buffer retry.
            if capacity.is_some_and(|capacity| {
                self.line
                    .len()
                    .checked_add(2)
                    .is_none_or(|needed| needed > capacity)
            }) {
                return Err(libc::ERANGE);
            }
            self.line_pending = false;
            let line = self
                .line
                .split(|&byte| byte == 0)
                .next()
                .unwrap_or_default();
            if let Some(entry) = parse_gshadow_file_line(line) {
                return Ok(Some(GshadowRecord {
                    entry,
                    input_len: self.line.len(),
                }));
            }
        }
    }
}

// SAFETY: owned TLS keeps this state boxed per thread. Answer pointers refer
// only to its own allocation and are rebuilt after any growth.
#[cfg(feature = "owned-tls-cache")]
unsafe impl Send for GshadowTlsStorage {}

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
        GSHADOW_TLS.with(|cell| callback(&mut cell.borrow_mut()))
    }
}

const GSHADOW_PATH: &str = "/etc/gshadow";
const GSHADOW_PATH_ENV: &str = "FRANKENLIBC_GSHADOW_PATH";

fn gshadow_source_path() -> PathBuf {
    std::env::var_os(GSHADOW_PATH_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(GSHADOW_PATH))
}

enum GshadowReadError {
    Open(c_int),
    Read(c_int),
}

impl GshadowReadError {
    fn code(&self) -> c_int {
        match self {
            Self::Open(error) | Self::Read(error) => *error,
        }
    }
}

fn read_gshadow_file() -> Result<Vec<u8>, GshadowReadError> {
    use std::io::Read;

    let mut file = std::fs::File::open(gshadow_source_path())
        .map_err(|error| GshadowReadError::Open(error.raw_os_error().unwrap_or(libc::EIO)))?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .map_err(|error| GshadowReadError::Read(error.raw_os_error().unwrap_or(libc::EIO)))?;
    Ok(content)
}

fn lookup_gshadow_record(
    name: &[u8],
    capacity: Option<usize>,
) -> Result<Option<GshadowRecord>, GshadowReadError> {
    let content = read_gshadow_file()?;
    if capacity.is_some_and(|capacity| capacity < 3) {
        return Err(GshadowReadError::Read(libc::ERANGE));
    }
    for physical_line in content.split_inclusive(|&byte| byte == b'\n') {
        if capacity.is_some_and(|capacity| {
            physical_line
                .len()
                .checked_add(2)
                .is_none_or(|needed| needed > capacity)
        }) {
            return Err(GshadowReadError::Read(libc::ERANGE));
        }
        let line = physical_line
            .split(|&byte| byte == 0)
            .next()
            .unwrap_or_default();
        if let Some(entry) = parse_gshadow_file_line(line)
            && entry.sg_namp == name
        {
            return Ok(Some(GshadowRecord {
                entry,
                input_len: physical_line.len(),
            }));
        }
    }
    Ok(None)
}

fn gshadow_errno() -> c_int {
    // SAFETY: the accessor returns the calling thread's initialized errno cell.
    unsafe { *crate::errno_abi::__errno_location() }
}

fn gshadow_error(error: c_int) -> c_int {
    // SAFETY: only the calling thread's errno is changed.
    unsafe { set_abi_errno(error) };
    error
}

/// Validate the two output objects before touching the caller's result slot.
unsafe fn prepare_gshadow_output(
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> Result<usize, c_int> {
    if result.is_null() || !tracked_object_fits(result) {
        return Err(libc::EINVAL);
    }
    // SAFETY: result is a checked writable caller-provided pointer slot.
    unsafe { *result = ptr::null_mut() };
    if result_buf.is_null() || buffer.is_null() || !tracked_object_fits(result_buf.cast::<Sgrp>()) {
        return Err(libc::EINVAL);
    }
    Ok(effective_buffer_len(buffer, buflen))
}

/// Pack all strings and both pointer lists in caller-owned storage, then
/// publish the separately supplied sgrp. No field is published on ERANGE.
unsafe fn pack_gshadow_caller(
    record: &GshadowRecord,
    result_buf: *mut Sgrp,
    buffer: *mut c_char,
    capacity: usize,
) -> c_int {
    let entry = &record.entry;
    let admins: Vec<&[u8]> = entry
        .sg_adm
        .split(|&byte| byte == b',')
        .filter(|name| !name.is_empty())
        .collect();
    let members: Vec<&[u8]> = entry
        .sg_mem
        .split(|&byte| byte == b',')
        .filter(|name| !name.is_empty())
        .collect();
    let pointer_size = std::mem::size_of::<*mut c_char>();
    let pointer_align = std::mem::align_of::<*mut c_char>();
    let layout = (|| {
        let name_end = entry.sg_namp.len().checked_add(1)?;
        let password_bytes = if entry.sg_passwd.is_empty() {
            0
        } else {
            entry.sg_passwd.len().checked_add(1)?
        };
        let names_offset = name_end.checked_add(password_bytes)?;
        let strings_end = admins
            .iter()
            .chain(&members)
            .try_fold(names_offset, |offset, name| {
                offset.checked_add(name.len())?.checked_add(1)
            })?;
        // GNU reserves the original input spelling, including delimiters and
        // any trailing newline, before its aligned pointer lists.
        let text_end = strings_end.max(record.input_len.checked_add(1)?);
        let address = (buffer as usize).checked_add(text_end)?;
        let padding = address.wrapping_neg() & (pointer_align - 1);
        let admins_offset = text_end.checked_add(padding)?;
        let admins_bytes = admins.len().checked_add(1)?.checked_mul(pointer_size)?;
        let members_offset = admins_offset.checked_add(admins_bytes)?;
        // The GNU parser also requires one spare, unwritten pointer after the
        // two terminating NULL slots. Preserve its ERANGE boundary.
        let members_bytes = members.len().checked_add(2)?.checked_mul(pointer_size)?;
        let needed = members_offset.checked_add(members_bytes)?;
        Some((
            name_end,
            names_offset,
            admins_offset,
            members_offset,
            needed,
        ))
    })();
    let Some((name_end, mut cursor, admins_offset, members_offset, needed)) = layout else {
        return libc::ERANGE;
    };
    if needed > capacity {
        return libc::ERANGE;
    }

    // SAFETY: the complete checked layout fits capacity. All pointer tables
    // are aligned relative to the actual caller buffer, including offsets.
    unsafe {
        ptr::copy_nonoverlapping(entry.sg_namp.as_ptr().cast(), buffer, entry.sg_namp.len());
        *buffer.add(entry.sg_namp.len()) = 0;
        let password = if entry.sg_passwd.is_empty() {
            buffer.add(entry.sg_namp.len())
        } else {
            let password = buffer.add(name_end);
            ptr::copy_nonoverlapping(
                entry.sg_passwd.as_ptr().cast(),
                password,
                entry.sg_passwd.len(),
            );
            *password.add(entry.sg_passwd.len()) = 0;
            password
        };
        let admin_slots = buffer.add(admins_offset).cast::<*mut c_char>();
        let member_slots = buffer.add(members_offset).cast::<*mut c_char>();
        for (list, slots) in [(&admins, admin_slots), (&members, member_slots)] {
            for (index, name) in list.iter().enumerate() {
                let destination = buffer.add(cursor);
                ptr::copy_nonoverlapping(name.as_ptr().cast(), destination, name.len());
                *destination.add(name.len()) = 0;
                slots.add(index).write(destination);
                cursor += name.len() + 1;
            }
            slots.add(list.len()).write(ptr::null_mut());
        }
        result_buf.write(Sgrp {
            sg_namp: buffer,
            sg_passwd: password,
            sg_adm: admin_slots,
            sg_mem: member_slots,
        });
    }
    0
}

fn pack_gshadow_into_static_storage(
    storage: &mut GshadowTlsStorage,
    entry: &GshadowRecord,
) -> Result<*mut c_void, c_int> {
    loop {
        if storage.buf.is_empty() {
            storage.buf.try_reserve(1024).map_err(|_| libc::ENOMEM)?;
            storage.buf.resize(1024, 0);
        }
        // SAFETY: entry is typed storage; the owned allocation stays live when
        // the TLS borrow ends. All pointers are rebuilt after each growth.
        let rc = unsafe {
            pack_gshadow_caller(
                entry,
                &raw mut storage.entry,
                storage.buf.as_mut_ptr().cast(),
                storage.buf.len(),
            )
        };
        if rc == 0 {
            return Ok((&raw mut storage.entry).cast());
        }
        if rc != libc::ERANGE {
            return Err(rc);
        }
        gshadow_error(libc::ERANGE);
        let next = storage.buf.len().checked_mul(2).ok_or(libc::ENOMEM)?;
        storage
            .buf
            .try_reserve(next - storage.buf.len())
            .map_err(|_| libc::ENOMEM)?;
        storage.buf.resize(next, 0);
    }
}

fn gshadow_to_static_sgrp(entry: &GshadowRecord) -> *mut c_void {
    match with_gshadow_storage(|storage| pack_gshadow_into_static_storage(storage, entry)) {
        Ok(result) => result,
        Err(error) => {
            gshadow_error(error);
            ptr::null_mut()
        }
    }
}

/// Open or rewind only the native files database, with an observable open error.
pub(crate) fn files_setsgent() -> c_int {
    with_gshadow_storage(|storage| {
        storage.close_files();
        storage.open_files().err().unwrap_or(0)
    })
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setsgent() {
    let saved_errno = gshadow_errno();
    let error = files_setsgent();
    // SAFETY: preserve errno on a successful rewind.
    unsafe { set_abi_errno(if error == 0 { saved_errno } else { error }) };
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endsgent() {
    let saved_errno = gshadow_errno();
    with_gshadow_storage(GshadowTlsStorage::close_files);
    // SAFETY: closing the iterator does not alter the caller's errno.
    unsafe { set_abi_errno(saved_errno) };
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsgent() -> *mut c_void {
    let saved_errno = gshadow_errno();
    let outcome = with_gshadow_storage(|storage| {
        if storage.open_files().is_err() {
            // GNU public enumeration maps an unavailable database to EOF.
            return Ok(ptr::null_mut());
        }
        let Some(entry) = storage.next_files_entry(None)? else {
            return Ok(ptr::null_mut());
        };
        let answer = pack_gshadow_into_static_storage(storage, &entry);
        if answer.is_err() {
            storage.pending = Some(entry);
        }
        answer
    });
    match outcome {
        Ok(result) => {
            // SAFETY: success and ordinary EOF preserve the caller's errno.
            unsafe { set_abi_errno(saved_errno) };
            result
        }
        Err(error) => {
            gshadow_error(error);
            ptr::null_mut()
        }
    }
}

/// The NSS files contract represents ordinary EOF as zero with a null result,
/// leaving a missing or unreadable database distinguishable from exhaustion.
pub(crate) unsafe fn files_getsgent_r(
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
    open_failure: &mut bool,
) -> c_int {
    *open_failure = false;
    let saved_errno = gshadow_errno();
    // SAFETY: forwarded reentrant output-storage contract.
    let capacity = match unsafe { prepare_gshadow_output(result_buf, buffer, buflen, result) } {
        Ok(capacity) => capacity,
        Err(error) => return gshadow_error(error),
    };
    let outcome = with_gshadow_storage(|storage| {
        if let Err(error) = storage.open_files() {
            *open_failure = true;
            return Err(error);
        }
        let Some(entry) = storage.next_files_entry(Some(capacity))? else {
            return Ok(());
        };
        // SAFETY: output objects are validated and the full pack is bounded.
        let rc = unsafe { pack_gshadow_caller(&entry, result_buf.cast(), buffer, capacity) };
        if rc != 0 {
            storage.pending = Some(entry);
            return Err(rc);
        }
        // SAFETY: publish the exact caller object only after complete packing.
        unsafe { *result = result_buf };
        Ok(())
    });
    match outcome {
        Ok(()) => {
            // SAFETY: internal reads/allocations do not change success errno.
            unsafe { set_abi_errno(saved_errno) };
            0
        }
        Err(error) => gshadow_error(error),
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsgent_r(
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    let saved_errno = gshadow_errno();
    let mut open_failure = false;
    // SAFETY: forward the same reentrant caller-storage contract.
    let rc = unsafe { files_getsgent_r(result_buf, buffer, buflen, result, &mut open_failure) };
    if open_failure {
        unsafe { set_abi_errno(saved_errno) };
        libc::ENOENT
    } else if rc == 0 && unsafe { (*result).is_null() } {
        libc::ENOENT
    } else {
        rc
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsgnam(name: *const c_char) -> *mut c_void {
    let Some(name_bytes) = (unsafe { bounded_cstr_bytes(name) }) else {
        gshadow_error(libc::EINVAL);
        return ptr::null_mut();
    };
    let saved_errno = gshadow_errno();
    let entry = match lookup_gshadow_record(name_bytes, None) {
        Ok(entry) => entry,
        Err(error) => {
            gshadow_error(error.code());
            return ptr::null_mut();
        }
    };
    unsafe { set_abi_errno(saved_errno) };
    entry
        .as_ref()
        .map_or(ptr::null_mut(), gshadow_to_static_sgrp)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsgnam_r(
    name: *const c_char,
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    let mut open_failure = false;
    // SAFETY: the public and files-provider callers use the same output ABI.
    unsafe { files_getsgnam_r(name, result_buf, buffer, buflen, result, &mut open_failure) }
}

pub(crate) unsafe fn files_getsgnam_r(
    name: *const c_char,
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
    open_failure: &mut bool,
) -> c_int {
    *open_failure = false;
    let saved_errno = gshadow_errno();
    // SAFETY: forwarded reentrant output-storage contract.
    let capacity = match unsafe { prepare_gshadow_output(result_buf, buffer, buflen, result) } {
        Ok(capacity) => capacity,
        Err(error) => return gshadow_error(error),
    };
    let Some(name_bytes) = (unsafe { bounded_cstr_bytes(name) }) else {
        return gshadow_error(libc::EINVAL);
    };
    let entry = match lookup_gshadow_record(name_bytes, Some(capacity)) {
        Ok(entry) => entry,
        Err(error) => {
            *open_failure = matches!(error, GshadowReadError::Open(_));
            return gshadow_error(error.code());
        }
    };
    if let Some(entry) = entry {
        // SAFETY: the validated output objects remain live during packing.
        let rc = unsafe { pack_gshadow_caller(&entry, result_buf.cast(), buffer, capacity) };
        if rc != 0 {
            return gshadow_error(rc);
        }
        // SAFETY: result_buf is now completely initialized.
        unsafe { *result = result_buf };
    }
    // SAFETY: a normal key miss is zero/null and preserves errno.
    unsafe { set_abi_errno(saved_errno) };
    0
}

/// Own the line allocation and stream lock across callbacks and foreign unwind.
/// No gshadow TLS borrow is held while a FILE operation can invoke user code.
struct GshadowStreamReader {
    stream: *mut c_void,
    line: *mut c_char,
    capacity: usize,
}

impl Drop for GshadowStreamReader {
    fn drop(&mut self) {
        let saved_errno = gshadow_errno();
        // SAFETY: getdelim supplies malloc-compatible storage, and this guard
        // owns one matching flockfile acquisition until the caller returns.
        unsafe {
            crate::malloc_abi::free(self.line.cast());
            crate::stdio_abi::funlockfile(self.stream);
            set_abi_errno(saved_errno);
        }
    }
}

impl GshadowStreamReader {
    unsafe fn new(stream: *mut c_void) -> Self {
        // SAFETY: the caller keeps a valid FILE alive for this entire guard.
        unsafe { crate::stdio_abi::flockfile(stream) };
        Self {
            stream,
            line: ptr::null_mut(),
            capacity: 0,
        }
    }

    unsafe fn rewind_error(&self, position: i64, error: c_int) -> c_int {
        if position >= 0
            && unsafe { crate::stdio_abi::fseeko(self.stream, position, libc::SEEK_SET) } == 0
        {
            error
        } else {
            let error = if position < 0 {
                libc::ESPIPE
            } else {
                let error = gshadow_errno();
                if error == 0 { libc::ESPIPE } else { error }
            };
            // A consumed record that cannot be retried is a stream error.
            unsafe { crate::stdio_abi::set_stream_error(self.stream) };
            error
        }
    }

    unsafe fn next(
        &mut self,
        save_position: bool,
        capacity: Option<usize>,
    ) -> Result<Option<(GshadowRecord, i64, c_int)>, c_int> {
        if capacity.is_some_and(|capacity| capacity < 3) {
            return Err(libc::ERANGE);
        }
        loop {
            let saved_errno = gshadow_errno();
            let position = if save_position {
                // SAFETY: the stream is live and locked by this guard.
                unsafe { crate::stdio_abi::ftello(self.stream) }
            } else {
                -1
            };
            // GNU permits reentrant reads from pipes, retaining the position
            // query's error on success. A seekable query preserves errno.
            let success_errno = if save_position && position < 0 {
                gshadow_errno()
            } else {
                saved_errno
            };
            unsafe { set_abi_errno(success_errno) };
            let length = unsafe {
                crate::stdio_abi::getdelim_for_caller(
                    &mut self.line,
                    &mut self.capacity,
                    b'\n' as c_int,
                    self.stream,
                    0,
                )
            };
            let read_errno = gshadow_errno();
            // getdelim may return positive partial bytes and still set ferror.
            // Such bytes are not a complete security-database record.
            if unsafe { crate::stdio_abi::ferror(self.stream) } != 0 {
                return Err(if read_errno == 0 {
                    libc::EIO
                } else {
                    read_errno
                });
            }
            if length < 0 {
                // Allocation failures are errors even if no stream flag was set.
                return if unsafe { crate::stdio_abi::feof(self.stream) } != 0 {
                    Ok(None)
                } else {
                    Err(if read_errno == 0 {
                        libc::EIO
                    } else {
                        read_errno
                    })
                };
            }
            if capacity.is_some_and(|capacity| {
                (length as usize)
                    .checked_add(2)
                    .is_none_or(|needed| needed > capacity)
            }) {
                return Err(unsafe { self.rewind_error(position, libc::ERANGE) });
            }
            // SAFETY: getdelim returned this many initialized bytes.
            let bytes =
                unsafe { std::slice::from_raw_parts(self.line.cast::<u8>(), length as usize) };
            let bytes = bytes.split(|&byte| byte == 0).next().unwrap_or_default();
            if let Some(entry) = parse_gshadow_file_line(bytes) {
                return Ok(Some((
                    GshadowRecord {
                        entry,
                        input_len: length as usize,
                    },
                    position,
                    success_errno,
                )));
            }
            unsafe { set_abi_errno(success_errno) };
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn fgetsgent(stream: *mut c_void) -> *mut c_void {
    if stream.is_null() {
        gshadow_error(libc::EINVAL);
        return ptr::null_mut();
    }
    let saved_errno = gshadow_errno();
    // SAFETY: a nonnull valid FILE is required by the public API.
    let mut reader = unsafe { GshadowStreamReader::new(stream) };
    // GNU's nonreentrant helper needs a seekable stream before consuming data.
    if unsafe { crate::stdio_abi::ftello(stream) } < 0 {
        return ptr::null_mut();
    }
    unsafe { set_abi_errno(saved_errno) };
    match unsafe { reader.next(false, None) } {
        Ok(Some((entry, _, success_errno))) => {
            unsafe { set_abi_errno(success_errno) };
            gshadow_to_static_sgrp(&entry)
        }
        Ok(None) => {
            gshadow_error(libc::ENOENT);
            ptr::null_mut()
        }
        Err(error) => {
            gshadow_error(error);
            ptr::null_mut()
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn fgetsgent_r(
    stream: *mut c_void,
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    let saved_errno = gshadow_errno();
    // SAFETY: forwarded reentrant output-storage contract.
    let capacity = match unsafe { prepare_gshadow_output(result_buf, buffer, buflen, result) } {
        Ok(capacity) => capacity,
        Err(error) => return gshadow_error(error),
    };
    if stream.is_null() {
        return gshadow_error(libc::EINVAL);
    }
    unsafe { set_abi_errno(saved_errno) };
    // SAFETY: a nonnull valid FILE is required by the public API.
    let mut reader = unsafe { GshadowStreamReader::new(stream) };
    let (entry, position, success_errno) = match unsafe { reader.next(true, Some(capacity)) } {
        Ok(Some(record)) => record,
        Ok(None) => return gshadow_error(libc::ENOENT),
        Err(error) => return gshadow_error(error),
    };
    // SAFETY: output objects passed validation and are kept live by the caller.
    let rc = unsafe { pack_gshadow_caller(&entry, result_buf.cast(), buffer, capacity) };
    if rc != 0 {
        let error = unsafe { reader.rewind_error(position, rc) };
        return gshadow_error(error);
    }
    // SAFETY: publish the caller's structure after all strings/lists are ready.
    unsafe {
        *result = result_buf;
        set_abi_errno(success_errno);
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sgetsgent(string: *const c_char) -> *mut c_void {
    let Some(line_bytes) = (unsafe { bounded_cstr_bytes(string) }) else {
        gshadow_error(libc::EINVAL);
        return ptr::null_mut();
    };
    match parse_gshadow_line(line_bytes) {
        Some(entry) => gshadow_to_static_sgrp(&GshadowRecord {
            entry,
            input_len: line_bytes.len(),
        }),
        None => ptr::null_mut(),
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sgetsgent_r(
    string: *const c_char,
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    let saved_errno = gshadow_errno();
    // Unlike a files lookup, GNU's initial string-copy ERANGE leaves the
    // result pointer untouched. Validate its object before preserving it.
    if result.is_null()
        || !tracked_object_fits(result)
        || result_buf.is_null()
        || !tracked_object_fits(result_buf.cast::<Sgrp>())
        || buffer.is_null()
    {
        return gshadow_error(libc::EINVAL);
    }
    let Some(line_bytes) = (unsafe { bounded_cstr_bytes(string) }) else {
        unsafe { *result = ptr::null_mut() };
        return gshadow_error(libc::EINVAL);
    };
    let capacity = effective_buffer_len(buffer, buflen);
    if line_bytes
        .len()
        .checked_add(1)
        .is_none_or(|needed| needed > capacity)
    {
        return gshadow_error(libc::ERANGE);
    }
    // SAFETY: forwarded reentrant output-storage contract.
    let capacity = match unsafe { prepare_gshadow_output(result_buf, buffer, buflen, result) } {
        Ok(capacity) => capacity,
        Err(error) => return gshadow_error(error),
    };
    let Some(entry) = parse_gshadow_line(line_bytes) else {
        return libc::ENOENT;
    };
    let entry = GshadowRecord {
        entry,
        input_len: line_bytes.len(),
    };
    // SAFETY: output objects are validated and the complete pack is bounded.
    let rc = unsafe { pack_gshadow_caller(&entry, result_buf.cast(), buffer, capacity) };
    if rc != 0 {
        return gshadow_error(rc);
    }
    // SAFETY: publish only the exact caller object, after complete initialization.
    unsafe {
        *result = result_buf;
        set_abi_errno(saved_errno);
    }
    0
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

// ---------------------------------------------------------------------------
// lckpwdf / ulckpwdf
// ---------------------------------------------------------------------------

struct PasswordFileLock {
    fd: AtomicI32,
    operation_pid: AtomicU32,
}

static PASSWORD_FILE_LOCK: PasswordFileLock = PasswordFileLock {
    fd: AtomicI32::new(-1),
    operation_pid: AtomicU32::new(0),
};

struct PasswordLockOperation<'a> {
    lock: &'a PasswordFileLock,
    pid: u32,
}

impl PasswordFileLock {
    fn enter(&self) -> PasswordLockOperation<'_> {
        let pid = raw_syscall::sys_getpid() as u32;
        loop {
            let owner = self.operation_pid.load(Ordering::Acquire);
            // After fork, a gate held by another parent thread has no owner in
            // the child. Adopt that gate, but retain the inherited descriptor:
            // record locks belong to the parent process, while the child must
            // still close its own inherited handle through ulckpwdf.
            if owner != pid {
                if self
                    .operation_pid
                    .compare_exchange(owner, pid, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return PasswordLockOperation { lock: self, pid };
                }
                continue;
            }
            // SAFETY: operation_pid is a live aligned atomic word. A release
            // wakes waiters; the expected-value check closes the lost-wake gap.
            let _ = unsafe {
                raw_syscall::sys_futex(
                    self.operation_pid.as_ptr(),
                    libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                    owner,
                    0,
                    0,
                    0,
                )
            };
        }
    }

    fn acquire(&self, path: &CStr) -> Result<bool, c_int> {
        // Publish an in-progress descriptor before waiting in F_SETLKW. A
        // second lckpwdf caller must reject a duplicate immediately rather than
        // taking the same process-owned kernel lock and reporting success.
        if self.fd.load(Ordering::Acquire) >= 0 {
            return Ok(false);
        }
        let _operation = self.enter();
        if self.fd.load(Ordering::Acquire) >= 0 {
            return Ok(false);
        }
        // SAFETY: path is NUL-terminated and remains live across openat.
        let fd = unsafe {
            raw_syscall::sys_openat(
                libc::AT_FDCWD,
                path.as_ptr().cast(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
                0o600,
            )
        }?;
        self.fd.store(fd, Ordering::Release);
        let result = (|| {
            let _alarm = PasswordLockAlarm::arm()?;
            let lock = libc::flock {
                l_type: libc::F_WRLCK as _,
                l_whence: libc::SEEK_SET as _,
                l_start: 0,
                l_len: 0,
                l_pid: 0,
            };
            // SAFETY: F_SETLKW reads the live flock. A zero length covers the
            // entire file, including future extensions. Unlike polling sleeps,
            // this preserves the kernel's SA_RESTART behavior for other signals.
            unsafe { raw_syscall::sys_fcntl(fd, libc::F_SETLKW, (&raw const lock) as usize) }
                .map(|_| true)
        })();
        if result.is_err() {
            self.fd.store(-1, Ordering::Release);
            // Linux closes a descriptor even when close reports EINTR. Do not
            // retry and risk closing a descriptor another thread has reused.
            let _ = raw_syscall::sys_close(fd);
        }
        result
    }

    fn release(&self) -> Result<bool, c_int> {
        let _operation = self.enter();
        let fd = self.fd.swap(-1, Ordering::AcqRel);
        if fd < 0 {
            return Ok(false);
        }
        // Closing releases this process's POSIX record lock. In a fork child it
        // closes only the child's handle, leaving the parent's lock intact.
        raw_syscall::sys_close(fd).map(|()| true)
    }
}

impl Drop for PasswordLockOperation<'_> {
    fn drop(&mut self) {
        if self
            .lock
            .operation_pid
            .compare_exchange(self.pid, 0, Ordering::Release, Ordering::Relaxed)
            .is_ok()
        {
            // SAFETY: the gate remains live and aligned while callers wait.
            let _ = unsafe {
                raw_syscall::sys_futex(
                    self.lock.operation_pid.as_ptr(),
                    libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                    i32::MAX as u32,
                    0,
                    0,
                    0,
                )
            };
        }
    }
}

// Use the kernel layout so restoring SIGALRM preserves the exact prior handler,
// flags, mask and restorer, including handlers installed by a host libc. Going
// through the public sigaction wrapper would introduce its dispatch trampoline.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PasswordLockSigaction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}

struct PasswordLockAlarm {
    old_action: PasswordLockSigaction,
    old_mask: u64,
    mask_changed: bool,
    armed: bool,
}

extern "C" fn password_lock_alarm_handler(_signal: c_int) {}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn frankenlibc_signal_restorer();
}

impl PasswordLockAlarm {
    fn arm() -> Result<Self, c_int> {
        let mut action = PasswordLockSigaction {
            handler: password_lock_alarm_handler as *const () as usize,
            // No SA_RESTART: expiration must interrupt the blocking record lock.
            mask: u64::MAX,
            ..PasswordLockSigaction::default()
        };
        #[cfg(target_arch = "x86_64")]
        {
            action.flags = 0x0400_0000; // Linux SA_RESTORER.
            action.restorer = frankenlibc_signal_restorer as *const () as usize;
        }
        let mut old_action = PasswordLockSigaction::default();
        // SAFETY: both structs use Linux's kernel sigaction layout and the
        // restorer is the existing native rt_sigreturn assembly entrypoint.
        unsafe {
            raw_syscall::sys_rt_sigaction(
                libc::SIGALRM,
                (&raw const action).cast(),
                (&raw mut old_action).cast(),
                size_of::<u64>(),
            )
        }?;
        let mut guard = Self {
            old_action,
            old_mask: 0,
            mask_changed: false,
            armed: false,
        };
        let alarm_bit = 1u64 << (libc::SIGALRM - 1);
        // SAFETY: the kernel reads/writes exactly one u64 signal-mask word.
        unsafe {
            raw_syscall::sys_rt_sigprocmask(
                libc::SIG_UNBLOCK,
                (&raw const alarm_bit).cast(),
                (&raw mut guard.old_mask).cast(),
                size_of::<u64>(),
            )
        }?;
        guard.mask_changed = true;
        let timer = libc::itimerval {
            it_interval: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            it_value: libc::timeval {
                tv_sec: 15,
                tv_usec: 0,
            },
        };
        // This deliberately shares alarm()/ITIMER_REAL, as GNU lckpwdf does:
        // an existing alarm is replaced, then canceled rather than restored.
        // SAFETY: timer is a valid itimerval; no old timer is requested.
        unsafe {
            raw_syscall::sys_setitimer(
                libc::ITIMER_REAL,
                (&raw const timer).cast(),
                ptr::null_mut(),
            )
        }?;
        guard.armed = true;
        Ok(guard)
    }
}

impl Drop for PasswordLockAlarm {
    fn drop(&mut self) {
        if self.armed {
            let timer = libc::itimerval {
                it_interval: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                it_value: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
            };
            // SAFETY: the zero interval timer cancels the temporary alarm.
            let _ = unsafe {
                raw_syscall::sys_setitimer(
                    libc::ITIMER_REAL,
                    (&raw const timer).cast(),
                    ptr::null_mut(),
                )
            };
        }
        if self.mask_changed {
            // SAFETY: restore the exact kernel mask captured for this thread.
            let _ = unsafe {
                raw_syscall::sys_rt_sigprocmask(
                    libc::SIG_SETMASK,
                    (&raw const self.old_mask).cast(),
                    ptr::null_mut(),
                    size_of::<u64>(),
                )
            };
        }
        // SAFETY: restore the exact kernel action captured by arm(). These
        // direct syscalls do not overwrite the lock operation's errno.
        let _ = unsafe {
            raw_syscall::sys_rt_sigaction(
                libc::SIGALRM,
                (&raw const self.old_action).cast(),
                ptr::null_mut(),
                size_of::<u64>(),
            )
        };
    }
}

fn password_lock_result(result: Result<bool, c_int>) -> c_int {
    match result {
        Ok(true) => 0,
        Ok(false) => -1,
        Err(error) => {
            unsafe { set_abi_errno(error) };
            -1
        }
    }
}

/// Acquire the process-wide password database lock with GNU's 15-second alarm
/// timeout. This temporarily uses SIGALRM and the process's alarm timer while
/// preserving the signal action and calling thread's mask. As with GNU lckpwdf,
/// applications must coordinate process-wide SIGALRM use between threads.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lckpwdf() -> c_int {
    password_lock_result(PASSWORD_FILE_LOCK.acquire(c"/etc/.pwd.lock"))
}

/// Release the password database lock. Without an owned descriptor, return -1
/// without changing errno, matching a duplicate lckpwdf call's convention.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ulckpwdf() -> c_int {
    password_lock_result(PASSWORD_FILE_LOCK.release())
}

/// Exercise the same lock implementation on a scratch file without changing
/// the production pathname or adding an environment-variable override.
#[doc(hidden)]
#[cfg(debug_assertions)]
pub fn lckpwdf_at_for_tests(path: &CStr) -> c_int {
    password_lock_result(PASSWORD_FILE_LOCK.acquire(path))
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
