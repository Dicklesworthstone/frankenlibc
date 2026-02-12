//! ABI layer for `<grp.h>` functions.
//!
//! Implements `getgrnam`, `getgrgid`, `getgrent`, `setgrent`, `endgrent`
//! using a files backend (parsing `/etc/group`).
//!
//! Returns pointers to thread-local static storage, matching glibc behavior
//! where each call overwrites the previous result.

use std::cell::RefCell;
use std::ffi::{c_char, c_int};
use std::ptr;

use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

/// Thread-local storage for the most recent group result.
struct GrpStorage {
    gr: libc::group,
    /// Concatenated NUL-terminated strings backing the group fields.
    buf: Vec<u8>,
    /// Pointer array for gr_mem (NULL-terminated).
    mem_ptrs: Vec<*mut c_char>,
    /// Cached file content.
    file_cache: Option<Vec<u8>>,
    /// Parsed entries for iteration.
    entries: Vec<glibc_rs_core::grp::Group>,
    /// Current iteration index for getgrent.
    iter_idx: usize,
}

impl GrpStorage {
    fn new() -> Self {
        Self {
            gr: unsafe { std::mem::zeroed() },
            buf: Vec::new(),
            mem_ptrs: Vec::new(),
            file_cache: None,
            entries: Vec::new(),
            iter_idx: 0,
        }
    }

    fn ensure_loaded(&mut self) {
        if self.file_cache.is_none() {
            self.file_cache = std::fs::read("/etc/group").ok();
        }
    }

    /// Populate the C struct from a parsed entry.
    fn fill_from(&mut self, entry: &glibc_rs_core::grp::Group) -> *mut libc::group {
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
}

thread_local! {
    static GRP_TLS: RefCell<GrpStorage> = RefCell::new(GrpStorage::new());
}

fn do_getgrnam(name: &[u8]) -> *mut libc::group {
    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.ensure_loaded();
        let content = storage.file_cache.clone().unwrap_or_default();
        match glibc_rs_core::grp::lookup_by_name(&content, name) {
            Some(entry) => storage.fill_from(&entry),
            None => ptr::null_mut(),
        }
    })
}

fn do_getgrgid(gid: u32) -> *mut libc::group {
    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.ensure_loaded();
        let content = storage.file_cache.clone().unwrap_or_default();
        match glibc_rs_core::grp::lookup_by_gid(&content, gid) {
            Some(entry) => storage.fill_from(&entry),
            None => ptr::null_mut(),
        }
    })
}

/// POSIX `getgrnam` — look up group entry by name.
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setgrent() {
    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.ensure_loaded();
        let content = storage.file_cache.clone().unwrap_or_default();
        storage.entries = glibc_rs_core::grp::parse_all(&content);
        storage.iter_idx = 0;
    });
}

/// POSIX `endgrent` — close group enumeration and free cached data.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn endgrent() {
    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        storage.entries.clear();
        storage.iter_idx = 0;
        storage.file_cache = None;
    });
}

/// POSIX `getgrent` — return the next group entry in iteration order.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrent() -> *mut libc::group {
    GRP_TLS.with(|cell| {
        let mut storage = cell.borrow_mut();
        if storage.entries.is_empty() && storage.iter_idx == 0 {
            storage.ensure_loaded();
            let content = storage.file_cache.clone().unwrap_or_default();
            storage.entries = glibc_rs_core::grp::parse_all(&content);
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
#[unsafe(no_mangle)]
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
    let entry = match glibc_rs_core::grp::lookup_by_name(&content, name_cstr.to_bytes()) {
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
#[unsafe(no_mangle)]
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
    let entry = match glibc_rs_core::grp::lookup_by_gid(&content, gid) {
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
    entry: &glibc_rs_core::grp::Group,
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
