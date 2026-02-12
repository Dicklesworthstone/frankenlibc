//! ABI layer for `<pwd.h>` functions.
//!
//! Implements `getpwnam`, `getpwuid`, `getpwent`, `setpwent`, `endpwent`
//! using a files backend (parsing `/etc/passwd`).
//!
//! Returns pointers to thread-local static storage, matching glibc behavior
//! where each call overwrites the previous result.

use std::cell::RefCell;
use std::ffi::{c_char, c_int};
use std::ptr;

use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

/// Thread-local storage for the most recent passwd result.
/// Holds the C-layout struct plus backing string buffers.
struct PwdStorage {
    pw: libc::passwd,
    /// Concatenated NUL-terminated strings backing the passwd fields.
    buf: Vec<u8>,
    /// Cached file content.
    file_cache: Option<Vec<u8>>,
    /// Parsed entries for iteration.
    entries: Vec<glibc_rs_core::pwd::Passwd>,
    /// Current iteration index for getpwent.
    iter_idx: usize,
}

impl PwdStorage {
    fn new() -> Self {
        Self {
            pw: unsafe { std::mem::zeroed() },
            buf: Vec::new(),
            file_cache: None,
            entries: Vec::new(),
            iter_idx: 0,
        }
    }

    /// Load /etc/passwd if not cached.
    fn ensure_loaded(&mut self) {
        if self.file_cache.is_none() {
            self.file_cache = std::fs::read("/etc/passwd").ok();
        }
    }

    /// Populate the C struct from a parsed entry.
    /// Returns a pointer to the thread-local `libc::passwd`.
    fn fill_from(&mut self, entry: &glibc_rs_core::pwd::Passwd) -> *mut libc::passwd {
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
}

thread_local! {
    static PWD_TLS: RefCell<PwdStorage> = RefCell::new(PwdStorage::new());
}

/// Read /etc/passwd and look up by name, returning a pointer to thread-local storage.
fn do_getpwnam(name: &[u8]) -> *mut libc::passwd {
    PWD_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.ensure_loaded();
        let content = storage.file_cache.clone().unwrap_or_default();
        match glibc_rs_core::pwd::lookup_by_name(&content, name) {
            Some(entry) => storage.fill_from(&entry),
            None => ptr::null_mut(),
        }
    })
}

/// Read /etc/passwd and look up by uid, returning a pointer to thread-local storage.
fn do_getpwuid(uid: u32) -> *mut libc::passwd {
    PWD_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.ensure_loaded();
        let content = storage.file_cache.clone().unwrap_or_default();
        match glibc_rs_core::pwd::lookup_by_uid(&content, uid) {
            Some(entry) => storage.fill_from(&entry),
            None => ptr::null_mut(),
        }
    })
}

/// POSIX `getpwnam` — look up passwd entry by username.
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setpwent() {
    PWD_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.ensure_loaded();
        let content = storage.file_cache.clone().unwrap_or_default();
        storage.entries = glibc_rs_core::pwd::parse_all(&content);
        storage.iter_idx = 0;
    });
}

/// POSIX `endpwent` — close the passwd enumeration and free cached data.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn endpwent() {
    PWD_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.entries.clear();
        storage.iter_idx = 0;
        storage.file_cache = None;
    });
}

/// POSIX `getpwent` — return the next passwd entry in iteration order.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwent() -> *mut libc::passwd {
    PWD_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        // If entries haven't been loaded, call setpwent implicitly.
        if storage.entries.is_empty() && storage.iter_idx == 0 {
            storage.ensure_loaded();
            let content = storage.file_cache.clone().unwrap_or_default();
            storage.entries = glibc_rs_core::pwd::parse_all(&content);
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
#[unsafe(no_mangle)]
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
    let entry = match glibc_rs_core::pwd::lookup_by_name(&content, name_bytes) {
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
#[unsafe(no_mangle)]
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
    let entry = match glibc_rs_core::pwd::lookup_by_uid(&content, uid) {
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
    entry: &glibc_rs_core::pwd::Passwd,
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
