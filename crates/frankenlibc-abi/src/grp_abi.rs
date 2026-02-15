//! ABI layer for `<grp.h>` functions.
//!
//! Implements `getgrnam`, `getgrgid`, `getgrent`, `setgrent`, `endgrent`
//! using a files backend (parsing `/etc/group`).
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

const GROUP_PATH: &str = "/etc/group";
const GROUP_PATH_ENV: &str = "FRANKENLIBC_GROUP_PATH";

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

/// Thread-local storage for the most recent group result.
struct GrpStorage {
    gr: libc::group,
    /// Concatenated NUL-terminated strings backing the group fields.
    buf: Vec<u8>,
    /// Pointer array for gr_mem (NULL-terminated).
    mem_ptrs: Vec<*mut c_char>,
    /// File path for group backend (defaults to /etc/group).
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
    entries: Vec<frankenlibc_core::grp::Group>,
    /// Parse accounting from the most recent `entries` build.
    #[allow(dead_code)]
    last_parse_stats: frankenlibc_core::grp::ParseStats,
    /// Current iteration index for getgrent.
    iter_idx: usize,
    /// Cache hit/miss/reload/invalidation counters.
    cache_metrics: CacheMetrics,
}

impl GrpStorage {
    fn new() -> Self {
        Self::new_with_path(Self::configured_source_path())
    }

    fn new_with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            gr: unsafe { std::mem::zeroed() },
            buf: Vec::new(),
            mem_ptrs: Vec::new(),
            source_path: path.into(),
            file_cache: None,
            cache_fingerprint: None,
            cache_generation: 0,
            entries_generation: 0,
            entries: Vec::new(),
            last_parse_stats: frankenlibc_core::grp::ParseStats::default(),
            iter_idx: 0,
            cache_metrics: CacheMetrics::default(),
        }
    }

    fn configured_source_path() -> PathBuf {
        std::env::var_os(GROUP_PATH_ENV)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(GROUP_PATH))
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
        self.last_parse_stats = frankenlibc_core::grp::ParseStats::default();
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
                    self.last_parse_stats = frankenlibc_core::grp::ParseStats::default();
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
                self.last_parse_stats = frankenlibc_core::grp::ParseStats::default();
            }
        }
    }

    fn current_content(&self) -> &[u8] {
        self.file_cache.as_deref().unwrap_or_default()
    }

    fn rebuild_entries(&mut self) {
        let (entries, stats) = frankenlibc_core::grp::parse_all_with_stats(self.current_content());
        self.entries = entries;
        self.last_parse_stats = stats;
        self.iter_idx = 0;
        self.entries_generation = self.cache_generation;
    }

    /// Populate the C struct from a parsed entry.
    fn fill_from(&mut self, entry: &frankenlibc_core::grp::Group) -> *mut libc::group {
        // Build buffer: name\0passwd\0member0\0member1\0...
        self.buf.clear();
        let name_off = 0;
        self.buf.extend_from_slice(&entry.gr_name);
        self.buf.push(0);
        let passwd_off = self.buf.len();
        self.buf.extend_from_slice(&entry.gr_passwd);
        self.buf.push(0);

        // Member strings
        let mut mem_offsets = Vec::with_capacity(entry.gr_mem.len());
        for member in &entry.gr_mem {
            mem_offsets.push(self.buf.len());
            self.buf.extend_from_slice(member);
            self.buf.push(0);
        }

        let base = self.buf.as_ptr() as *mut c_char;

        // Build the NULL-terminated pointer array for gr_mem
        self.mem_ptrs.clear();
        for off in &mem_offsets {
            // SAFETY: offsets are within buf allocation.
            self.mem_ptrs.push(unsafe { base.add(*off) });
        }
        self.mem_ptrs.push(ptr::null_mut()); // NULL terminator

        // SAFETY: offsets are within buf allocation. Pointers are stable
        // because we don't resize buf/mem_ptrs again until the next fill_from call.
        self.gr = libc::group {
            gr_name: unsafe { base.add(name_off) },
            gr_passwd: unsafe { base.add(passwd_off) },
            gr_gid: entry.gr_gid,
            gr_mem: self.mem_ptrs.as_mut_ptr(),
        };

        &mut self.gr as *mut libc::group
    }

    #[cfg(test)]
    fn cache_metrics(&self) -> CacheMetrics {
        self.cache_metrics
    }
}

thread_local! {
    static GRP_TLS: RefCell<GrpStorage> = RefCell::new(GrpStorage::new());
}

fn do_getgrnam(name: &[u8]) -> *mut libc::group {
    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.refresh_cache();
        match frankenlibc_core::grp::lookup_by_name(storage.current_content(), name) {
            Some(entry) => storage.fill_from(&entry),
            None => ptr::null_mut(),
        }
    })
}

fn do_getgrgid(gid: u32) -> *mut libc::group {
    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.refresh_cache();
        match frankenlibc_core::grp::lookup_by_gid(storage.current_content(), gid) {
            Some(entry) => storage.fill_from(&entry),
            None => ptr::null_mut(),
        }
    })
}

/// POSIX `getgrnam` — look up group entry by name.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgrnam(name: *const c_char) -> *mut libc::group {
    if name.is_null() {
        return ptr::null_mut();
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Resolver, name as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    // SAFETY: name is non-null.
    let name_cstr = unsafe { std::ffi::CStr::from_ptr(name) };
    let result = do_getgrnam(name_cstr.to_bytes());
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, result.is_null());
    result
}

/// POSIX `getgrgid` — look up group entry by group ID.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgrgid(gid: libc::gid_t) -> *mut libc::group {
    let (_, decision) = runtime_policy::decide(ApiFamily::Resolver, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    let result = do_getgrgid(gid);
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, result.is_null());
    result
}

/// POSIX `setgrent` — rewind the group iteration cursor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setgrent() {
    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.refresh_cache();
        storage.rebuild_entries();
    });
}

/// POSIX `endgrent` — close group enumeration and free cached data.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endgrent() {
    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        if storage.file_cache.is_some() || !storage.entries.is_empty() {
            storage.cache_metrics.invalidations += 1;
        }
        storage.entries.clear();
        storage.iter_idx = 0;
        storage.file_cache = None;
        storage.cache_fingerprint = None;
        storage.entries_generation = 0;
        storage.last_parse_stats = frankenlibc_core::grp::ParseStats::default();
    });
}

/// POSIX `getgrent` — return the next group entry in iteration order.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgrent() -> *mut libc::group {
    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.refresh_cache();

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

/// POSIX `getgrnam_r` — reentrant version of `getgrnam`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgrnam_r(
    name: *const c_char,
    grp: *mut libc::group,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::group,
) -> c_int {
    if name.is_null() || grp.is_null() || buf.is_null() || result.is_null() {
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
    let content = std::fs::read("/etc/group").unwrap_or_default();
    let entry = match frankenlibc_core::grp::lookup_by_name(&content, name_cstr.to_bytes()) {
        Some(e) => e,
        None => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, false);
            return 0;
        }
    };

    let rc = unsafe { fill_group_r(&entry, grp, buf, buflen, result) };
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, rc != 0);
    rc
}

/// POSIX `getgrgid_r` — reentrant version of `getgrgid`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgrgid_r(
    gid: libc::gid_t,
    grp: *mut libc::group,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::group,
) -> c_int {
    if grp.is_null() || buf.is_null() || result.is_null() {
        return libc::EINVAL;
    }

    // SAFETY: result is non-null.
    unsafe { *result = ptr::null_mut() };

    let (_, decision) = runtime_policy::decide(ApiFamily::Resolver, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return libc::EACCES;
    }

    let content = std::fs::read("/etc/group").unwrap_or_default();
    let entry = match frankenlibc_core::grp::lookup_by_gid(&content, gid) {
        Some(e) => e,
        None => {
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, false);
            return 0;
        }
    };

    let rc = unsafe { fill_group_r(&entry, grp, buf, buflen, result) };
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, rc != 0);
    rc
}

/// Fill a caller-provided `libc::group` and string buffer for `_r` variants.
///
/// Buffer layout: name\0passwd\0mem0\0mem1\0...\0 [padding] [ptr_array]
///
/// # Safety
///
/// `grp`, `buf`, `result` must be valid writable pointers. `buflen` must
/// reflect the actual size of the `buf` allocation.
unsafe fn fill_group_r(
    entry: &frankenlibc_core::grp::Group,
    grp: *mut libc::group,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::group,
) -> c_int {
    // Calculate needed string space
    let str_needed = entry.gr_name.len()
        + 1
        + entry.gr_passwd.len()
        + 1
        + entry.gr_mem.iter().map(|m| m.len() + 1).sum::<usize>();

    // Pointer array needs (n_members + 1) * sizeof(*mut c_char), aligned
    let n_ptrs = entry.gr_mem.len() + 1;
    let ptr_size = std::mem::size_of::<*mut c_char>();
    let ptr_align = std::mem::align_of::<*mut c_char>();

    // Align the pointer array start
    let str_end = str_needed;
    let ptr_start = (str_end + ptr_align - 1) & !(ptr_align - 1);
    let total_needed = ptr_start + n_ptrs * ptr_size;

    if buflen < total_needed {
        return libc::ERANGE;
    }

    let base = buf;
    let mut off = 0usize;

    // SAFETY: all writes are within [buf, buf+buflen) since total_needed <= buflen.
    unsafe {
        // gr_name
        let name_ptr = base.add(off);
        ptr::copy_nonoverlapping(
            entry.gr_name.as_ptr().cast::<c_char>(),
            name_ptr,
            entry.gr_name.len(),
        );
        *base.add(off + entry.gr_name.len()) = 0;
        off += entry.gr_name.len() + 1;

        // gr_passwd
        let passwd_ptr = base.add(off);
        ptr::copy_nonoverlapping(
            entry.gr_passwd.as_ptr().cast::<c_char>(),
            passwd_ptr,
            entry.gr_passwd.len(),
        );
        *base.add(off + entry.gr_passwd.len()) = 0;
        off += entry.gr_passwd.len() + 1;

        // Member strings
        let ptr_array = base.add(ptr_start).cast::<*mut c_char>();
        for (i, member) in entry.gr_mem.iter().enumerate() {
            let mem_ptr = base.add(off);
            ptr::copy_nonoverlapping(member.as_ptr().cast::<c_char>(), mem_ptr, member.len());
            *base.add(off + member.len()) = 0;
            off += member.len() + 1;
            *ptr_array.add(i) = mem_ptr;
        }
        // NULL terminator for the pointer array
        *ptr_array.add(entry.gr_mem.len()) = ptr::null_mut();

        (*grp) = libc::group {
            gr_name: name_ptr,
            gr_passwd: passwd_ptr,
            gr_gid: entry.gr_gid,
            gr_mem: ptr_array,
        };

        *result = grp;
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
        fs::write(path, content).expect("temporary group file should be writable");
    }

    #[test]
    fn grp_cache_refresh_tracks_hits_and_reloads() {
        let path = temp_path("grp-cache");
        write_file(&path, b"root:x:0:\nusers:x:100:alice\n");

        let mut storage = GrpStorage::new_with_path(&path);
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

        write_file(&path, b"root:x:0:\nusers:x:101:alice,bob\n");
        storage.refresh_cache();
        let metrics = storage.cache_metrics();
        assert_eq!(metrics.misses, 2);
        assert_eq!(metrics.reloads, 2);
        assert_eq!(metrics.invalidations, 1);
        assert_eq!(storage.iter_idx, 0);
        assert!(
            frankenlibc_core::grp::lookup_by_gid(storage.current_content(), 101).is_some(),
            "cache reload should expose updated group content"
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn grp_rebuild_entries_records_parse_stats_after_invalidation() {
        let path = temp_path("grp-parse-stats");
        write_file(&path, b"root:x:0:\nmalformed\n#comment\n");

        let mut storage = GrpStorage::new_with_path(&path);
        storage.refresh_cache();
        storage.rebuild_entries();

        assert_eq!(storage.entries.len(), 1);
        assert_eq!(storage.last_parse_stats.parsed_entries, 1);
        assert_eq!(storage.last_parse_stats.malformed_lines, 1);
        assert_eq!(storage.last_parse_stats.skipped_lines, 1);
        assert_eq!(storage.entries_generation, storage.cache_generation);

        storage.iter_idx = 1;
        write_file(&path, b"root:x:0:\nusers:x:100:alice,bob\n");
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
