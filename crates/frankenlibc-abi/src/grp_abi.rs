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

use frankenlibc_core::errno;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::util::scan_c_string;

const GROUP_PATH: &str = "/etc/group";
const GROUP_PATH_ENV: &str = "FRANKENLIBC_GROUP_PATH";

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
    known_remaining(ptr as usize).is_none_or(|remaining| remaining >= std::mem::size_of::<T>())
}

fn effective_buffer_len(ptr: *const c_char, requested: libc::size_t) -> libc::size_t {
    known_remaining(ptr as usize).map_or(requested, |remaining| remaining.min(requested))
}

fn group_string_space(entry: &frankenlibc_core::grp::Group) -> Option<usize> {
    let mut needed = entry.gr_name.len().checked_add(1)?;
    needed = needed.checked_add(entry.gr_passwd.len())?.checked_add(1)?;
    for member in &entry.gr_mem {
        needed = needed.checked_add(member.len())?.checked_add(1)?;
    }
    Some(needed)
}

fn aligned_offset_from(base: *const c_char, offset: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two());
    let addr = (base as usize).checked_add(offset)?;
    let padding = addr.wrapping_neg() & (align - 1);
    offset.checked_add(padding)
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
    /// Most recent backend I/O error encountered while refreshing the cache.
    last_io_error: Option<c_int>,
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
            last_io_error: None,
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
                    });
                let had_cache = self.file_cache.is_some();

                self.file_cache = Some(bytes);
                self.cache_fingerprint = Some(next_fp);
                self.cache_generation = self.cache_generation.wrapping_add(1);
                self.cache_metrics.reloads += 1;
                self.last_io_error = None;

                if had_cache {
                    self.entries.clear();
                    self.iter_idx = 0;
                    self.entries_generation = 0;
                    self.last_parse_stats = frankenlibc_core::grp::ParseStats::default();
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
                self.iter_idx = 0;
                self.entries_generation = 0;
                self.last_parse_stats = frankenlibc_core::grp::ParseStats::default();
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

/// Fill thread-local group struct from a parsed entry.
/// Used by `fgetgrent` in `unistd_abi` to avoid duplicating TLS storage.
pub(crate) fn fill_group_from_entry(entry: &frankenlibc_core::grp::Group) -> *mut libc::group {
    GRP_TLS.with(|cell| cell.borrow_mut().fill_from(entry))
}

fn lookup_group_by_name(name: &[u8]) -> Option<frankenlibc_core::grp::Group> {
    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.refresh_cache();
        frankenlibc_core::grp::lookup_by_name(storage.current_content(), name)
    })
}

fn lookup_group_by_gid(gid: u32) -> Option<frankenlibc_core::grp::Group> {
    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.refresh_cache();
        frankenlibc_core::grp::lookup_by_gid(storage.current_content(), gid)
    })
}

fn group_backend_io_error() -> Option<c_int> {
    GRP_TLS.with(|cell| cell.borrow().backend_io_error())
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
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    let Some(name_bytes) = (unsafe { bounded_cstr_bytes(name) }) else {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    };
    let result = do_getgrnam(name_bytes);
    if result.is_null()
        && let Some(err) = group_backend_io_error()
    {
        unsafe { set_abi_errno(err) };
    }
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, result.is_null());
    result
}

/// POSIX `getgrgid` — look up group entry by group ID.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgrgid(gid: libc::gid_t) -> *mut libc::group {
    let (_, decision) = runtime_policy::decide(ApiFamily::Resolver, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    let result = do_getgrgid(gid);
    if result.is_null()
        && let Some(err) = group_backend_io_error()
    {
        unsafe { set_abi_errno(err) };
    }
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
    if !tracked_object_fits(result as *const *mut libc::group) {
        return libc::EINVAL;
    }

    // SAFETY: result is non-null.
    unsafe { *result = ptr::null_mut() };
    if !tracked_object_fits(grp as *const libc::group) {
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
    let entry = match lookup_group_by_name(name_bytes) {
        Some(e) => e,
        None => {
            if let Some(err) = group_backend_io_error() {
                runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
                return err;
            }
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, false);
            return 0;
        }
    };

    let rc = unsafe { fill_group_r(&entry, grp, buf, effective_buffer_len(buf, buflen), result) };
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
    if !tracked_object_fits(result as *const *mut libc::group) {
        return libc::EINVAL;
    }

    // SAFETY: result is non-null.
    unsafe { *result = ptr::null_mut() };
    if !tracked_object_fits(grp as *const libc::group) {
        return libc::EINVAL;
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Resolver, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return libc::EACCES;
    }

    let entry = match lookup_group_by_gid(gid) {
        Some(e) => e,
        None => {
            if let Some(err) = group_backend_io_error() {
                runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
                return err;
            }
            runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, false);
            return 0;
        }
    };

    let rc = unsafe { fill_group_r(&entry, grp, buf, effective_buffer_len(buf, buflen), result) };
    runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, rc != 0);
    rc
}

/// Fill a caller-provided `libc::group` and string buffer for `_r` variants.
///
/// Buffer layout: name\0passwd\0mem0\0mem1\0...\0 [padding] [ptr_array]
///
/// # Safety
///
/// `grp`, `buf`, `result` must be valid writable pointers. `buflen` must be
/// capped to the actual writable size of `buf`.
unsafe fn fill_group_r(
    entry: &frankenlibc_core::grp::Group,
    grp: *mut libc::group,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::group,
) -> c_int {
    // Calculate needed string space
    let Some(str_needed) = group_string_space(entry) else {
        return libc::ERANGE;
    };

    // Pointer array needs (n_members + 1) * sizeof(*mut c_char), aligned
    let Some(n_ptrs) = entry.gr_mem.len().checked_add(1) else {
        return libc::ERANGE;
    };
    let ptr_size = std::mem::size_of::<*mut c_char>();
    let ptr_align = std::mem::align_of::<*mut c_char>();

    let base = buf;

    // Align the pointer array address, not just the offset, because callers
    // may pass an interior byte pointer as their scratch buffer.
    let Some(ptr_start) = aligned_offset_from(base, str_needed, ptr_align) else {
        return libc::ERANGE;
    };
    let Some(ptr_bytes) = n_ptrs.checked_mul(ptr_size) else {
        return libc::ERANGE;
    };
    let Some(total_needed) = ptr_start.checked_add(ptr_bytes) else {
        return libc::ERANGE;
    };

    if buflen < total_needed {
        return libc::ERANGE;
    }

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

/// GNU `getgrent_r` — reentrant version of `getgrent`.
///
/// Iterates through `/etc/group` entries, filling a caller-provided buffer.
/// Returns 0 on success, `ENOENT` at end of file, `ERANGE` if buffer too small.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgrent_r(
    grp: *mut libc::group,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::group,
) -> c_int {
    if grp.is_null() || buf.is_null() || result.is_null() {
        return libc::EINVAL;
    }
    if !tracked_object_fits(result as *const *mut libc::group) {
        return libc::EINVAL;
    }

    unsafe { *result = ptr::null_mut() };
    if !tracked_object_fits(grp as *const libc::group) {
        return libc::EINVAL;
    }

    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
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
            unsafe { fill_group_r(&entry, grp, buf, effective_buffer_len(buf, buflen), result) };
        if rc == 0 {
            storage.iter_idx += 1;
        }
        rc
    })
}

// ---------------------------------------------------------------------------
// gid_from_group / group_from_gid (BSD libutil pwcache)
// ---------------------------------------------------------------------------
//
// Mirrors of uid_from_user / user_from_uid (pwd_abi), wrapping
// getgrnam/getgrgid with the same "lookup or report" interface used
// by ls -l, find -group, etc.

/// BSD `gid_from_group(name, gid)` — look up the gid for `name` and
/// store it through `*gid`. Returns 0 on success, -1 if `name` is
/// NULL or no matching group exists.
///
/// # Safety
///
/// `name` must be a valid NUL-terminated C string or NULL. `gid`,
/// when non-NULL, must point to writable `gid_t` storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gid_from_group(name: *const c_char, gid: *mut libc::gid_t) -> c_int {
    if name.is_null() {
        return -1;
    }
    // SAFETY: caller-supplied C string.
    let g = unsafe { getgrnam(name) };
    if g.is_null() {
        return -1;
    }
    if !gid.is_null() {
        // SAFETY: g is a valid group struct returned by our getgrnam.
        unsafe { *gid = (*g).gr_gid };
    }
    0
}

/// BSD `group_from_gid(gid, nogroup)` — return a pointer to a static
/// C string with the group name matching `gid`. If no group matches:
/// * with `nogroup == 0`, returns NULL;
/// * with `nogroup != 0`, formats `gid` as decimal ASCII into a
///   process-static buffer and returns its pointer.
///
/// The returned pointer is owned by the runtime and remains valid
/// until the next call to `group_from_gid` from any thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn group_from_gid(gid: libc::gid_t, nogroup: c_int) -> *const c_char {
    use std::sync::Mutex;
    static FALLBACK: Mutex<[u8; 24]> = Mutex::new([0; 24]);

    // SAFETY: getgrgid returns either NULL or a group in process-
    // static storage owned by our grp_abi machinery.
    let g = unsafe { getgrgid(gid) };
    if !g.is_null() {
        // SAFETY: gr_name is a valid C string in the same static storage.
        let name = unsafe { (*g).gr_name };
        if !name.is_null() {
            return name as *const c_char;
        }
    }
    if nogroup == 0 {
        return std::ptr::null();
    }

    let mut guard = FALLBACK.lock().unwrap_or_else(|p| p.into_inner());
    let buf: &mut [u8; 24] = &mut guard;
    let mut tmp = [0u8; 23];
    let mut len = 0usize;
    let mut v = gid as u64;
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
