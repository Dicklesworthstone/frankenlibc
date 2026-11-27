//! GNU-owned private dependencies of interposed NSS service modules.
//!
//! A loaded `libnss_compat` calls back into libc for its action lists, files,
//! and private netgroup cursors. Those objects belong to the host provider;
//! substituting a native Rust cursor or FILE would mix incompatible ownership
//! and layouts. Interpose forwards this complete dependency chain to the same
//! host libc. The standalone resolver never exposes host symbols, so these
//! helpers report ENOSYS there instead of fabricating an empty database.

use std::ffi::{c_char, c_int, c_void};

fn resolve(symbol: &'static str) -> Option<usize> {
    // SAFETY: the canonical errno cell belongs to this calling thread.
    let saved_errno = unsafe { *crate::errno_abi::__errno_location() };
    // This resolver reads the host object's own ELF definition rather than
    // using interposable dlsym scope. Do not compare it with the address of
    // our exported veneer: in a dlopen-local DSO that reference can itself be
    // preempted by the host, falsely rejecting the correct host callback.
    let address = crate::host_resolve::resolve_host_symbol_raw(symbol);
    // SAFETY: discovering the host must not alter the callback's input errno.
    unsafe { crate::errno_abi::set_abi_errno(saved_errno) };
    address
}

unsafe fn fail(error: c_int, errnop: *mut c_int) {
    // SAFETY: errno belongs to this thread; a nonnull errnop is a writable
    // error cell under the private NSS callback contract.
    unsafe {
        crate::errno_abi::set_abi_errno(error);
        if !errnop.is_null() {
            errnop.write(error);
        }
    }
}

/// Open a GNU-owned FILE for a host NSS module, including its close-on-exec
/// and stream setup semantics. The caller closes it through the same owner.
pub(crate) unsafe fn files_fopen(path: *const c_char) -> *mut c_void {
    if path.is_null() {
        // SAFETY: no external output cell is supplied.
        unsafe { fail(libc::EINVAL, std::ptr::null_mut()) };
        return std::ptr::null_mut();
    }
    let Some(address) = resolve("__nss_files_fopen") else {
        // SAFETY: no external output cell is supplied.
        unsafe { fail(libc::ENOSYS, std::ptr::null_mut()) };
        return std::ptr::null_mut();
    };
    type Callback = unsafe extern "C" fn(*const c_char) -> *mut c_void;
    // SAFETY: the host export has the private NSS fopen declaration. The
    // caller keeps its terminated path alive throughout this operation.
    let callback: Callback = unsafe { core::mem::transmute(address) };
    unsafe { callback(path) }
}

/// Return the host's opaque action list. Database identifiers come from the
/// calling GNU module; the bridge neither remaps them nor caches the list.
pub(crate) unsafe fn database_get(database: c_int, actions: *mut *mut c_void) -> bool {
    if actions.is_null() || database < 0 {
        // SAFETY: failure leaves the caller's opaque output untouched.
        unsafe { fail(libc::EINVAL, std::ptr::null_mut()) };
        return false;
    }
    let Some(address) = resolve("__nss_database_get") else {
        // SAFETY: no external error cell is supplied.
        unsafe { fail(libc::ENOSYS, std::ptr::null_mut()) };
        return false;
    };
    type Callback = unsafe extern "C" fn(c_int, *mut *mut c_void) -> bool;
    // SAFETY: nss_database.h declares a C bool, not int. The output slot is
    // writable and the database identifier is a valid host enumeration value.
    let callback: Callback = unsafe { core::mem::transmute(address) };
    unsafe { callback(database, actions) }
}

/// Resolve a callback in a GNU-owned action-list entry. Never interpret that
/// pointer as one of FrankenLibC's native Service values.
pub(crate) unsafe fn lookup_function(service: *mut c_void, function: *const c_char) -> *mut c_void {
    if service.is_null() || function.is_null() {
        // SAFETY: no external output cell is supplied.
        unsafe { fail(libc::EINVAL, std::ptr::null_mut()) };
        return std::ptr::null_mut();
    }
    let Some(address) = resolve("__nss_lookup_function") else {
        // SAFETY: no external output cell is supplied.
        unsafe { fail(libc::ENOSYS, std::ptr::null_mut()) };
        return std::ptr::null_mut();
    };
    type Callback = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
    // SAFETY: the service was supplied by the host's database_get and remains
    // host-owned; the terminated callback name is live for the entire call.
    let callback: Callback = unsafe { core::mem::transmute(address) };
    unsafe { callback(service, function) }
}

/// Initialize the host module's private netgroup cursor in its own storage.
pub(crate) unsafe fn setnetgrent(group: *const c_char, state: *mut c_void) -> c_int {
    if group.is_null() || state.is_null() {
        // SAFETY: no external error cell is supplied.
        unsafe { fail(libc::EINVAL, std::ptr::null_mut()) };
        return 0;
    }
    let Some(address) = resolve("__internal_setnetgrent") else {
        // SAFETY: unavailable setup publishes no fake initialized cursor.
        unsafe { fail(libc::ENOSYS, std::ptr::null_mut()) };
        return 0;
    };
    type Callback = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;
    // SAFETY: GNU's private declaration takes a group and its caller-owned
    // __netgrent. Only the host accesses this opaque object's layout.
    let callback: Callback = unsafe { core::mem::transmute(address) };
    unsafe { callback(group, state) }
}

/// Advance one independently owned GNU cursor with the exact caller buffer.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn getnetgrent_r(
    host: *mut *mut c_char,
    user: *mut *mut c_char,
    domain: *mut *mut c_char,
    state: *mut c_void,
    buffer: *mut c_char,
    length: usize,
    errnop: *mut c_int,
) -> c_int {
    if host.is_null()
        || user.is_null()
        || domain.is_null()
        || state.is_null()
        || buffer.is_null()
        || errnop.is_null()
    {
        // SAFETY: the optional error cell is writable by the NSS contract.
        unsafe { fail(libc::EINVAL, errnop) };
        return 0;
    }
    let Some(address) = resolve("__internal_getnetgrent_r") else {
        // SAFETY: the complete error cell was supplied above.
        unsafe { fail(libc::ENOSYS, errnop) };
        return 0;
    };
    type Callback = unsafe extern "C" fn(
        *mut *mut c_char,
        *mut *mut c_char,
        *mut *mut c_char,
        *mut c_void,
        *mut c_char,
        usize,
        *mut c_int,
    ) -> c_int;
    // SAFETY: this is the private header's signature; the host initialized
    // state and owns its allocations. All caller outputs remain writable.
    let callback: Callback = unsafe { core::mem::transmute(address) };
    unsafe { callback(host, user, domain, state, buffer, length, errnop) }
}

/// Release a GNU cursor through the same owner. This ABI returns void.
pub(crate) unsafe fn endnetgrent(state: *mut c_void) {
    if state.is_null() {
        // SAFETY: no external error cell is supplied.
        unsafe { fail(libc::EINVAL, std::ptr::null_mut()) };
        return;
    }
    let Some(address) = resolve("__internal_endnetgrent") else {
        // SAFETY: standalone never created host-owned state to release.
        unsafe { fail(libc::ENOSYS, std::ptr::null_mut()) };
        return;
    };
    type Callback = unsafe extern "C" fn(*mut c_void);
    // SAFETY: the private declaration returns void. The host owns every
    // pointer in its caller-owned cursor and performs the matching cleanup.
    let callback: Callback = unsafe { core::mem::transmute(address) };
    unsafe { callback(state) };
}
