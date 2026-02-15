//! ABI layer for `<pwd.h>` functions.
//!
//! Implements `getpwnam`, `getpwuid`, `getpwent`, `setpwent`, `endpwent`
//! using a files backend (parsing `/etc/passwd`).
//!
//! Returns pointers to thread-local static storage, matching glibc behavior
//! where each call overwrites the previous result.

use std::cell::RefCell;
use std::ffi::{c_char, c_int};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::UNIX_EPOCH;

use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

const PASSWD_PATH: &str = "/etc/passwd";
const PASSWD_PATH_ENV: &str = "FRANKENLIBC_PASSWD_PATH";

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

/// Thread-local storage for the most recent passwd result.
/// Holds the C-layout struct plus backing string buffers.
struct PwdStorage {
    pw: libc::passwd,
    /// Concatenated NUL-terminated strings backing the passwd fields.
    buf: Vec<u8>,
    /// File path for passwd backend (defaults to /etc/passwd).
    source_path: PathBuf,
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
}

impl PwdStorage {
    fn new() -> Self {
        Self::new_with_path(Self::configured_source_path())
    }

    fn new_with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            pw: unsafe { std::mem::zeroed() },
            buf: Vec::new(),
            source_path: path.into(),
            file_cache: None,
            cache_fingerprint: None,
            cache_generation: 0,
            entries_generation: 0,
            entries: Vec::new(),
            last_parse_stats: frankenlibc_core::pwd::ParseStats::default(),
            iter_idx: 0,
            cache_metrics: CacheMetrics::default(),
        }
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
        if self.file_cache.is_some() || !self.entries.is_empty() {
            self.cache_metrics.invalidations += 1;
        }
        self.file_cache = None;
        self.cache_fingerprint = None;
        self.entries.clear();
        self.iter_idx = 0;
        self.entries_generation = 0;
        self.last_parse_stats = frankenlibc_core::pwd::ParseStats::default();
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

    /// Refresh cache from disk when fingerprint changes.
    ///
    /// Invalidation policy:
    /// - cache hit: retain parsed entries/cursor
    /// - reload or read failure: drop parsed entries and reset cursor
    fn refresh_cache(&mut self) {
        self.refresh_source_path_from_env();
        let current_fp = Self::file_fingerprint(&self.source_path);

        if let (Some(_), Some(cached_fp), Some(now_fp)) =
            (&self.file_cache, self.cache_fingerprint, current_fp)
            && cached_fp == now_fp
        {
            self.cache_metrics.hits += 1;
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
                    });
                let had_cache = self.file_cache.is_some();

                self.file_cache = Some(bytes);
                self.cache_fingerprint = Some(next_fp);
                self.cache_generation = self.cache_generation.wrapping_add(1);
                self.cache_metrics.reloads += 1;

                if had_cache {
                    self.entries.clear();
                    self.iter_idx = 0;
                    self.entries_generation = 0;
                    self.last_parse_stats = frankenlibc_core::pwd::ParseStats::default();
                    self.cache_metrics.invalidations += 1;
                }
            }
            Err(_) => {
                if self.file_cache.is_some() || !self.entries.is_empty() {
                    self.cache_metrics.invalidations += 1;
                }
                self.file_cache = None;
                self.cache_fingerprint = None;
                self.entries.clear();
                self.iter_idx = 0;
                self.entries_generation = 0;
                self.last_parse_stats = frankenlibc_core::pwd::ParseStats::default();
            }
        }
    }

    fn current_content(&self) -> &[u8] {
        self.file_cache.as_deref().unwrap_or_default()
    }

    fn rebuild_entries(&mut self) {
        let (entries, stats) = frankenlibc_core::pwd::parse_all_with_stats(self.current_content());
        self.entries = entries;
        self.last_parse_stats = stats;
        self.iter_idx = 0;
        self.entries_generation = self.cache_generation;
    }

    /// Populate the C struct from a parsed entry.
    /// Returns a pointer to the thread-local `libc::passwd`.
    fn fill_from(&mut self, entry: &frankenlibc_core::pwd::Passwd) -> *mut libc::passwd {
        // Build a buffer: name\0passwd\0gecos\0dir\0shell\0
        self.buf.clear();
        let name_off = 0;
        self.buf.extend_from_slice(&entry.pw_name);
        self.buf.push(0);
        let passwd_off = self.buf.len();
        self.buf.extend_from_slice(&entry.pw_passwd);
        self.buf.push(0);
        let gecos_off = self.buf.len();
        self.buf.extend_from_slice(&entry.pw_gecos);
        self.buf.push(0);
        let dir_off = self.buf.len();
        self.buf.extend_from_slice(&entry.pw_dir);
        self.buf.push(0);
        let shell_off = self.buf.len();
        self.buf.extend_from_slice(&entry.pw_shell);
        self.buf.push(0);

        let base = self.buf.as_ptr() as *mut c_char;
        // SAFETY: offsets are within the buf allocation. Pointers are stable
        // because we don't resize buf again until the next fill_from call.
        self.pw = libc::passwd {
            pw_name: unsafe { base.add(name_off) },
            pw_passwd: unsafe { base.add(passwd_off) },
            pw_uid: entry.pw_uid,
            pw_gid: entry.pw_gid,
            pw_gecos: unsafe { base.add(gecos_off) },
            pw_dir: unsafe { base.add(dir_off) },
            pw_shell: unsafe { base.add(shell_off) },
        };

        &mut self.pw as *mut libc::passwd
    }

    #[cfg(test)]
    fn cache_metrics(&self) -> CacheMetrics {
        self.cache_metrics
    }
}

thread_local! {
    static PWD_TLS: RefCell<PwdStorage> = RefCell::new(PwdStorage::new());
}

/// Read /etc/passwd and look up by name, returning a pointer to thread-local storage.
fn do_getpwnam(name: &[u8]) -> *mut libc::passwd {
    PWD_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.refresh_cache();
        match frankenlibc_core::pwd::lookup_by_name(storage.current_content(), name) {
            Some(entry) => storage.fill_from(&entry),
            None => ptr::null_mut(),
        }
    })
}

/// Read /etc/passwd and look up by uid, returning a pointer to thread-local storage.
fn do_getpwuid(uid: u32) -> *mut libc::passwd {
    PWD_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.refresh_cache();
        match frankenlibc_core::pwd::lookup_by_uid(storage.current_content(), uid) {
            Some(entry) => storage.fill_from(&entry),
            None => ptr::null_mut(),
        }
    })
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
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    // SAFETY: name is non-null; compute length to build a byte slice.
    let name_cstr = unsafe { std::ffi::CStr::from_ptr(name) };
    let result = do_getpwnam(name_cstr.to_bytes());
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, result.is_null());
    result
}

/// POSIX `getpwuid` — look up passwd entry by user ID.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpwuid(uid: libc::uid_t) -> *mut libc::passwd {
    let (_, decision) = runtime_policy::decide(ApiFamily::Resolver, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    let result = do_getpwuid(uid);
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, result.is_null());
    result
}

/// POSIX `setpwent` — rewind the passwd iteration cursor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpwent() {
    PWD_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.refresh_cache();
        storage.rebuild_entries();
    });
}

/// POSIX `endpwent` — close the passwd enumeration and free cached data.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endpwent() {
    PWD_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        if storage.file_cache.is_some() || !storage.entries.is_empty() {
            storage.cache_metrics.invalidations += 1;
        }
        storage.entries.clear();
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
    PWD_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.refresh_cache();

        // If entries haven't been loaded, call setpwent implicitly.
        if (storage.entries.is_empty() && storage.iter_idx == 0)
            || storage.entries_generation != storage.cache_generation
        {
            storage.rebuild_entries();
        }

        if storage.iter_idx >= storage.entries.len() {
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

    // SAFETY: result is non-null.
    unsafe { *result = ptr::null_mut() };

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Resolver, name as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return libc::EACCES;
    }

    // SAFETY: name is non-null.
    let name_cstr = unsafe { std::ffi::CStr::from_ptr(name) };
    let name_bytes = name_cstr.to_bytes();

    let content = std::fs::read("/etc/passwd").unwrap_or_default();
    let entry = match frankenlibc_core::pwd::lookup_by_name(&content, name_bytes) {
        Some(e) => e,
        None => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, false);
            return 0; // Not found, *result remains NULL
        }
    };

    let rc = unsafe { fill_passwd_r(&entry, pwd, buf, buflen, result) };
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

    // SAFETY: result is non-null.
    unsafe { *result = ptr::null_mut() };

    let (_, decision) = runtime_policy::decide(ApiFamily::Resolver, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return libc::EACCES;
    }

    let content = std::fs::read("/etc/passwd").unwrap_or_default();
    let entry = match frankenlibc_core::pwd::lookup_by_uid(&content, uid) {
        Some(e) => e,
        None => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, false);
            return 0;
        }
    };

    let rc = unsafe { fill_passwd_r(&entry, pwd, buf, buflen, result) };
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, rc != 0);
    rc
}

/// Fill a caller-provided `libc::passwd` and string buffer for `_r` variants.
///
/// # Safety
///
/// `pwd`, `buf`, `result` must be valid writable pointers. `buflen` must
/// reflect the actual size of the `buf` allocation.
unsafe fn fill_passwd_r(
    entry: &frankenlibc_core::pwd::Passwd,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::passwd,
) -> c_int {
    // Calculate needed buffer: name\0passwd\0gecos\0dir\0shell\0
    let needed = entry.pw_name.len()
        + 1
        + entry.pw_passwd.len()
        + 1
        + entry.pw_gecos.len()
        + 1
        + entry.pw_dir.len()
        + 1
        + entry.pw_shell.len()
        + 1;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_path(prefix: &str) -> PathBuf {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "frankenlibc-{prefix}-{}-{seq}.txt",
            std::process::id()
        ))
    }

    fn write_file(path: &Path, content: &[u8]) {
        fs::write(path, content).expect("temporary passwd file should be writable");
    }

    #[test]
    fn pwd_cache_refresh_tracks_hits_and_reloads() {
        let path = temp_path("pwd-cache");
        write_file(
            &path,
            b"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh\n",
        );

        let mut storage = PwdStorage::new_with_path(&path);
        storage.refresh_cache();
        let metrics = storage.cache_metrics();
        assert_eq!(metrics.misses, 1);
        assert_eq!(metrics.hits, 0);
        assert_eq!(metrics.reloads, 1);
        assert_eq!(metrics.invalidations, 0);

        storage.refresh_cache();
        let metrics = storage.cache_metrics();
        assert_eq!(metrics.hits, 1);
        assert_eq!(metrics.misses, 1);
        assert_eq!(metrics.reloads, 1);

        write_file(
            &path,
            b"root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/sh\n",
        );
        storage.refresh_cache();
        let metrics = storage.cache_metrics();
        assert_eq!(metrics.misses, 2);
        assert_eq!(metrics.reloads, 2);
        assert_eq!(metrics.invalidations, 1);
        assert_eq!(storage.iter_idx, 0);
        assert!(
            frankenlibc_core::pwd::lookup_by_uid(storage.current_content(), 1001).is_some(),
            "cache reload should expose updated passwd content"
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn pwd_rebuild_entries_records_parse_stats_after_invalidation() {
        let path = temp_path("pwd-parse-stats");
        write_file(
            &path,
            b"root:x:0:0:root:/root:/bin/bash\nbad_line\n#comment\n",
        );

        let mut storage = PwdStorage::new_with_path(&path);
        storage.refresh_cache();
        storage.rebuild_entries();

        assert_eq!(storage.entries.len(), 1);
        assert_eq!(storage.last_parse_stats.parsed_entries, 1);
        assert_eq!(storage.last_parse_stats.malformed_lines, 1);
        assert_eq!(storage.last_parse_stats.skipped_lines, 1);
        assert_eq!(storage.entries_generation, storage.cache_generation);

        storage.iter_idx = 1;
        write_file(
            &path,
            b"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh\n",
        );
        storage.refresh_cache();

        assert!(
            storage.entries.is_empty(),
            "cache invalidation should clear iteration entries"
        );
        assert_eq!(storage.iter_idx, 0);
        assert_eq!(storage.entries_generation, 0);

        storage.rebuild_entries();
        assert_eq!(storage.entries.len(), 2);
        assert_eq!(storage.last_parse_stats.parsed_entries, 2);
        assert_eq!(storage.last_parse_stats.malformed_lines, 0);
        assert_eq!(storage.entries_generation, storage.cache_generation);

        let _ = fs::remove_file(&path);
    }
}
