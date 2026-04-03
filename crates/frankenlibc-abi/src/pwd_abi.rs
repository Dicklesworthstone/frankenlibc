//! ABI layer for `<pwd.h>` functions.
//!
//! Implements `getpwnam`, `getpwuid`, `getpwent`, `setpwent`, `endpwent`
//! using a files backend (parsing `/etc/passwd`).
//!
//! Returns pointers to thread-local static storage, matching glibc behavior
//! where each call overwrites the previous result.

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::UNIX_EPOCH;

use frankenlibc_core::errno;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
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
    /// Most recent backend I/O error encountered while refreshing the cache.
    last_io_error: Option<c_int>,
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
            last_io_error: None,
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

/// Fill thread-local passwd struct from a parsed entry.
/// Used by `fgetpwent` in `unistd_abi` to avoid duplicating TLS storage.
pub(crate) fn fill_passwd_from_entry(entry: &frankenlibc_core::pwd::Passwd) -> *mut libc::passwd {
    PWD_TLS.with(|cell| cell.borrow_mut().fill_from(entry))
}

fn lookup_passwd_by_name(name: &[u8]) -> Option<frankenlibc_core::pwd::Passwd> {
    PWD_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.refresh_cache();
        frankenlibc_core::pwd::lookup_by_name(storage.current_content(), name)
    })
}

fn lookup_passwd_by_uid(uid: u32) -> Option<frankenlibc_core::pwd::Passwd> {
    PWD_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.refresh_cache();
        frankenlibc_core::pwd::lookup_by_uid(storage.current_content(), uid)
    })
}

fn passwd_backend_io_error() -> Option<c_int> {
    PWD_TLS.with(|cell| cell.borrow().backend_io_error())
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
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
        return ptr::null_mut();
    }

    // SAFETY: name is non-null; compute length to build a byte slice.
    let name_cstr = unsafe { std::ffi::CStr::from_ptr(name) };
    let result = do_getpwnam(name_cstr.to_bytes());
    if result.is_null()
        && let Some(err) = passwd_backend_io_error()
    {
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

    let result = do_getpwuid(uid);
    if result.is_null()
        && let Some(err) = passwd_backend_io_error()
    {
        unsafe { set_abi_errno(err) };
    }
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

    let entry = match lookup_passwd_by_name(name_bytes) {
        Some(e) => e,
        None => {
            if let Some(err) = passwd_backend_io_error() {
                runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
                return err;
            }
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

    let entry = match lookup_passwd_by_uid(uid) {
        Some(e) => e,
        None => {
            if let Some(err) = passwd_backend_io_error() {
                runtime_policy::observe(ApiFamily::Resolver, decision.profile, 15, true);
                return err;
            }
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

    unsafe { *result = ptr::null_mut() };

    PWD_TLS.with(|cell| {
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
        storage.iter_idx += 1;
        unsafe { fill_passwd_r(&entry, pwd, buf, buflen, result) }
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

thread_local! {
    static SHADOW_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static SHADOW_ENTRY: RefCell<SpwdEntry> = const { RefCell::new(SpwdEntry {
        sp_namp: ptr::null_mut(),
        sp_pwdp: ptr::null_mut(),
        sp_lstchg: -1,
        sp_min: -1,
        sp_max: -1,
        sp_warn: -1,
        sp_inact: -1,
        sp_expire: -1,
        sp_flag: 0,
    }) };
    static SHADOW_ITER_IDX: RefCell<usize> = const { RefCell::new(0) };
    static SHADOW_CACHE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn parse_shadow_field(s: &str) -> i64 {
    if s.is_empty() {
        -1
    } else {
        s.parse::<i64>().unwrap_or(-1)
    }
}

/// Fill SpwdEntry from a shadow line. Returns true on success.
fn fill_shadow_entry(line: &str, buf: &mut Vec<u8>, entry: &mut SpwdEntry) -> bool {
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 8 {
        return false;
    }

    buf.clear();
    // Pack name and password into buf as null-terminated strings
    let name = parts[0];
    let pass = parts[1];
    buf.extend_from_slice(name.as_bytes());
    buf.push(0);
    let pass_offset = buf.len();
    buf.extend_from_slice(pass.as_bytes());
    buf.push(0);

    entry.sp_namp = buf.as_mut_ptr() as *mut c_char;
    entry.sp_pwdp = unsafe { buf.as_mut_ptr().add(pass_offset) as *mut c_char };
    entry.sp_lstchg = parse_shadow_field(parts[2]);
    entry.sp_min = parse_shadow_field(parts[3]);
    entry.sp_max = parse_shadow_field(parts[4]);
    entry.sp_warn = parse_shadow_field(parts[5]);
    entry.sp_inact = parse_shadow_field(parts[6]);
    entry.sp_expire = parse_shadow_field(parts[7]);
    entry.sp_flag = if parts.len() > 8 {
        parts[8].parse::<u64>().unwrap_or(0)
    } else {
        0
    };
    true
}

/// `getspnam` — look up a shadow entry by login name.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getspnam(name: *const c_char) -> *mut c_void {
    if name.is_null() {
        return ptr::null_mut();
    }
    let name_str = unsafe { std::ffi::CStr::from_ptr(name) };
    let name_str = match name_str.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let content = match std::fs::read_to_string(SHADOW_PATH) {
        Ok(c) => c,
        Err(_) => {
            unsafe { set_abi_errno(libc::EACCES) };
            return ptr::null_mut();
        }
    };

    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some(colon) = line.find(':')
            && &line[..colon] == name_str
        {
            return SHADOW_BUF.with(|buf| {
                SHADOW_ENTRY.with(|entry| {
                    let mut buf = buf.borrow_mut();
                    let mut entry = entry.borrow_mut();
                    if fill_shadow_entry(line, &mut buf, &mut entry) {
                        &mut *entry as *mut SpwdEntry as *mut c_void
                    } else {
                        ptr::null_mut()
                    }
                })
            });
        }
    }
    ptr::null_mut()
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
    unsafe { *result = ptr::null_mut() };

    let name_str = unsafe { std::ffi::CStr::from_ptr(name) };
    let name_str = match name_str.to_str() {
        Ok(s) => s,
        Err(_) => return libc::EINVAL,
    };

    let content = match std::fs::read_to_string(SHADOW_PATH) {
        Ok(c) => c,
        Err(_) => return libc::EACCES,
    };

    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some(colon) = line.find(':')
            && &line[..colon] == name_str
        {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 8 {
                return libc::ENOENT;
            }

            // Pack into caller's buffer
            let name_bytes = parts[0].as_bytes();
            let pass_bytes = parts[1].as_bytes();
            let needed = name_bytes.len() + 1 + pass_bytes.len() + 1;
            if needed > buflen {
                return libc::ERANGE;
            }

            let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, buflen) };
            buf_slice[..name_bytes.len()].copy_from_slice(name_bytes);
            buf_slice[name_bytes.len()] = 0;
            let pass_off = name_bytes.len() + 1;
            buf_slice[pass_off..pass_off + pass_bytes.len()].copy_from_slice(pass_bytes);
            buf_slice[pass_off + pass_bytes.len()] = 0;

            let sp = spbuf as *mut SpwdEntry;
            unsafe {
                (*sp).sp_namp = buf;
                (*sp).sp_pwdp = buf.add(pass_off);
                (*sp).sp_lstchg = parse_shadow_field(parts[2]);
                (*sp).sp_min = parse_shadow_field(parts[3]);
                (*sp).sp_max = parse_shadow_field(parts[4]);
                (*sp).sp_warn = parse_shadow_field(parts[5]);
                (*sp).sp_inact = parse_shadow_field(parts[6]);
                (*sp).sp_expire = parse_shadow_field(parts[7]);
                (*sp).sp_flag = if parts.len() > 8 {
                    parts[8].parse::<u64>().unwrap_or(0)
                } else {
                    0
                };
                *result = spbuf;
            };
            return 0;
        }
    }
    libc::ENOENT
}

/// `setspent` — rewind the shadow database iterator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn setspent() {
    SHADOW_ITER_IDX.with(|idx| *idx.borrow_mut() = 0);
    SHADOW_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        cache.clear();
        if let Ok(content) = std::fs::read_to_string(SHADOW_PATH) {
            for line in content.lines() {
                if !line.starts_with('#') && !line.trim().is_empty() && line.contains(':') {
                    cache.push(line.to_string());
                }
            }
        }
    });
}

/// `endspent` — close the shadow database.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn endspent() {
    SHADOW_ITER_IDX.with(|idx| *idx.borrow_mut() = 0);
    SHADOW_CACHE.with(|cache| cache.borrow_mut().clear());
}

/// `getspent` — read the next shadow entry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getspent() -> *mut c_void {
    SHADOW_CACHE.with(|cache| {
        let cache = cache.borrow();
        SHADOW_ITER_IDX.with(|idx| {
            let mut idx = idx.borrow_mut();
            if *idx >= cache.len() {
                return ptr::null_mut();
            }
            let line = &cache[*idx];
            *idx += 1;
            SHADOW_BUF.with(|buf| {
                SHADOW_ENTRY.with(|entry| {
                    let mut buf = buf.borrow_mut();
                    let mut entry = entry.borrow_mut();
                    if fill_shadow_entry(line, &mut buf, &mut entry) {
                        &mut *entry as *mut SpwdEntry as *mut c_void
                    } else {
                        ptr::null_mut()
                    }
                })
            })
        })
    })
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
    unsafe { *result = ptr::null_mut() };

    SHADOW_CACHE.with(|cache| {
        let cache = cache.borrow();
        SHADOW_ITER_IDX.with(|idx| {
            let mut idx = idx.borrow_mut();
            if *idx >= cache.len() {
                return libc::ENOENT;
            }
            let line = &cache[*idx];
            *idx += 1;

            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 8 {
                return libc::ENOENT;
            }

            let name_bytes = parts[0].as_bytes();
            let pass_bytes = parts[1].as_bytes();
            let needed = name_bytes.len() + 1 + pass_bytes.len() + 1;
            if needed > buflen {
                // Rewind so caller can retry with larger buffer
                *idx -= 1;
                return libc::ERANGE;
            }

            let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, buflen) };
            buf_slice[..name_bytes.len()].copy_from_slice(name_bytes);
            buf_slice[name_bytes.len()] = 0;
            let pass_off = name_bytes.len() + 1;
            buf_slice[pass_off..pass_off + pass_bytes.len()].copy_from_slice(pass_bytes);
            buf_slice[pass_off + pass_bytes.len()] = 0;

            let sp = spbuf as *mut SpwdEntry;
            unsafe {
                (*sp).sp_namp = buf;
                (*sp).sp_pwdp = buf.add(pass_off);
                (*sp).sp_lstchg = parse_shadow_field(parts[2]);
                (*sp).sp_min = parse_shadow_field(parts[3]);
                (*sp).sp_max = parse_shadow_field(parts[4]);
                (*sp).sp_warn = parse_shadow_field(parts[5]);
                (*sp).sp_inact = parse_shadow_field(parts[6]);
                (*sp).sp_expire = parse_shadow_field(parts[7]);
                (*sp).sp_flag = if parts.len() > 8 {
                    parts[8].parse::<u64>().unwrap_or(0)
                } else {
                    0
                };
                *result = spbuf;
            };
            0
        })
    })
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

use frankenlibc_core::pwd::gshadow::{Gshadow, lookup_gshadow_by_name, parse_gshadow_line};

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

thread_local! {
    static GSHADOW_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static GSHADOW_ENUM_OFFSET: RefCell<usize> = const { RefCell::new(0) };
}

/// Read /etc/gshadow content. Returns None if file doesn't exist.
fn read_gshadow_file() -> Option<Vec<u8>> {
    std::fs::read("/etc/gshadow").ok()
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

    // Split comma-separated lists.
    let adm_list: Vec<&[u8]> = if entry.sg_adm.is_empty() {
        vec![]
    } else {
        entry.sg_adm.split(|&b| b == b',').collect()
    };
    let mem_list: Vec<&[u8]> = if entry.sg_mem.is_empty() {
        vec![]
    } else {
        entry.sg_mem.split(|&b| b == b',').collect()
    };

    // Calculate total space needed.
    let name_len = entry.sg_namp.len() + 1;
    let passwd_len = entry.sg_passwd.len() + 1;
    let adm_ptrs_size = (adm_list.len() + 1) * core::mem::size_of::<*mut c_char>();
    let mem_ptrs_size = (mem_list.len() + 1) * core::mem::size_of::<*mut c_char>();
    let adm_strs_size: usize = adm_list.iter().map(|s| s.len() + 1).sum();
    let mem_strs_size: usize = mem_list.iter().map(|s| s.len() + 1).sum();
    let total = sgrp_size
        + name_len
        + passwd_len
        + adm_ptrs_size
        + mem_ptrs_size
        + adm_strs_size
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
    GSHADOW_BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        buf.resize(GSHADOW_BUF_SIZE, 0);
        let ptr = unsafe { pack_gshadow_into_buf(entry, buf.as_mut_ptr(), GSHADOW_BUF_SIZE) };
        ptr as *mut c_void
    })
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setsgent() {
    GSHADOW_ENUM_OFFSET.with(|off| *off.borrow_mut() = 0);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endsgent() {
    GSHADOW_ENUM_OFFSET.with(|off| *off.borrow_mut() = 0);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsgent() -> *mut c_void {
    let content = match read_gshadow_file() {
        Some(c) => c,
        None => return ptr::null_mut(),
    };
    GSHADOW_ENUM_OFFSET.with(|off| {
        let mut offset = off.borrow_mut();
        let remaining = if *offset < content.len() {
            &content[*offset..]
        } else {
            return ptr::null_mut();
        };
        for line in remaining.split(|&b| b == b'\n') {
            *offset += line.len() + 1; // +1 for the newline
            if let Some(entry) = parse_gshadow_line(line) {
                return gshadow_to_static_sgrp(&entry);
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
    GSHADOW_ENUM_OFFSET.with(|off| {
        let mut offset = off.borrow_mut();
        let remaining = if *offset < content.len() {
            &content[*offset..]
        } else {
            return libc::ENOENT;
        };
        for line in remaining.split(|&b| b == b'\n') {
            *offset += line.len() + 1;
            if let Some(entry) = parse_gshadow_line(line) {
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
    let name_cstr = unsafe { std::ffi::CStr::from_ptr(name) };
    let content = match read_gshadow_file() {
        Some(c) => c,
        None => return ptr::null_mut(),
    };
    match lookup_gshadow_by_name(&content, name_cstr.to_bytes()) {
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
    let name_cstr = unsafe { std::ffi::CStr::from_ptr(name) };
    let content = match read_gshadow_file() {
        Some(c) => c,
        None => return libc::ENOENT,
    };
    match lookup_gshadow_by_name(&content, name_cstr.to_bytes()) {
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
    let cstr = unsafe { std::ffi::CStr::from_ptr(string) };
    match parse_gshadow_line(cstr.to_bytes()) {
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
    let cstr = unsafe { std::ffi::CStr::from_ptr(string) };
    match parse_gshadow_line(cstr.to_bytes()) {
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
pub unsafe extern "C" fn putsgent(_sgrp: *const c_void, _stream: *mut c_void) -> c_int {
    -1 // not supported
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
