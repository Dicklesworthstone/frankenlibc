//! Legacy resolver entry points share the calling thread's public `_res`.
//!
//! `__res_state` returns stable, initially zeroed storage. Unlike res_nmkquery,
//! the legacy APIs initialize that storage before use. After initialization,
//! every call observes public caller overrides through the native state engine.

use std::ffi::{c_char, c_int, c_void};

use super::{DNS_HEADER_SIZE, RES_INIT, checked_state, fail, fits};

unsafe fn current() -> Result<*mut c_void, c_int> {
    // SAFETY: __res_state returns this thread's aligned, live state storage.
    let pointer = unsafe { crate::glibc_internal_abi::__res_state() };
    // Do not retain a reference across init or a resolver operation.
    if unsafe { checked_state(pointer)? }.options & RES_INIT == 0
        && unsafe { super::init_impl(pointer, true) } != 0
    {
        // SAFETY: initialization set this thread's errno on failure.
        return Err(unsafe { *crate::errno_abi::__errno_location() });
    }
    Ok(pointer)
}

pub unsafe fn init() -> c_int {
    // SAFETY: exclusively accessed state owned by the calling thread.
    unsafe { super::init_impl(crate::glibc_internal_abi::__res_state(), true) }
}

unsafe fn query_state(name: *const c_char, answer: *mut c_void, capacity: c_int) -> Result<*mut c_void, c_int> {
    if name.is_null() || capacity < DNS_HEADER_SIZE as c_int
        || !fits(answer as usize, capacity.max(0) as usize)
    {
        // SAFETY: no caller pointers are dereferenced on this error path.
        unsafe { *crate::resolv_abi::__h_errno_location() = super::NO_RECOVERY };
        return Err(libc::EINVAL);
    }
    // SAFETY: current initializes only the calling thread's native state.
    unsafe { current() }
}

pub unsafe fn query(name: *const c_char, class: c_int, kind: c_int, answer: *mut c_void, capacity: c_int) -> c_int {
    // SAFETY: validate output before initialization or network activity.
    match unsafe { query_state(name, answer, capacity) } {
        Ok(pointer) => unsafe { super::query(pointer, name, class, kind, answer, capacity) },
        Err(error) => fail(error),
    }
}

pub unsafe fn search(name: *const c_char, class: c_int, kind: c_int, answer: *mut c_void, capacity: c_int) -> c_int {
    // SAFETY: input/output validation and native state initialization precede I/O.
    match unsafe { query_state(name, answer, capacity) } {
        Ok(pointer) => unsafe { super::search(pointer, name, class, kind, answer, capacity) },
        Err(error) => fail(error),
    }
}

pub unsafe fn querydomain(name: *const c_char, domain: *const c_char, class: c_int, kind: c_int, answer: *mut c_void, capacity: c_int) -> c_int {
    // SAFETY: native querydomain copies both strings before writing any output.
    match unsafe { query_state(name, answer, capacity) } {
        Ok(pointer) => unsafe { super::querydomain(pointer, name, domain, class, kind, answer, capacity) },
        Err(error) => fail(error),
    }
}

pub unsafe fn mkquery(op: c_int, name: *const c_char, class: c_int, kind: c_int,
    data: *const c_void, datalen: c_int, newrr: *const c_void, buffer: *mut c_void, capacity: c_int,
) -> c_int {
    if name.is_null() || capacity < DNS_HEADER_SIZE as c_int
        || !fits(buffer as usize, capacity.max(0) as usize)
    {
        return fail(libc::EINVAL);
    }
    // Unlike res_nmkquery, legacy res_mkquery performs implicit initialization.
    // SAFETY: current returns this thread's exclusively accessed state; the
    // native builder validates and copies strings before writing the output.
    match unsafe { current() } {
        Ok(pointer) => unsafe { super::mkquery(pointer, op, name, class, kind, data, datalen, newrr, buffer, capacity) },
        Err(error) => fail(error),
    }
}

pub unsafe fn send(message: *const c_void, length: c_int, answer: *mut c_void, capacity: c_int) -> c_int {
    if !(DNS_HEADER_SIZE as c_int..=u16::MAX as c_int).contains(&length)
        || capacity < DNS_HEADER_SIZE as c_int
        || !fits(message as usize, length.max(0) as usize)
        || !fits(answer as usize, capacity.max(0) as usize)
    {
        return fail(libc::EINVAL);
    }
    // SAFETY: both advertised spans were checked. Native send snapshots state
    // and ends its immutable message borrow before writing a possibly shared
    // answer buffer. It preserves TCP's full-length and UDP's copied-length ABI.
    match unsafe { current() } {
        Ok(pointer) => unsafe { super::send(pointer, message, length, answer, capacity) },
        Err(error) => fail(error),
    }
}
