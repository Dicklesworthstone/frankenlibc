//! NetBSD `efun(3)` family — "exit-on-failure" wrappers around
//! plain libc allocation/string/IO routines.
//!
//! Each wrapper here calls the corresponding non-`e`-prefixed
//! function and, on failure, invokes the globally-installed error
//! callback (which by default writes a brief diagnostic to stderr
//! and calls `exit(EXIT_FAILURE)`). Callers that prefer to recover
//! from failure can install a custom callback via [`esetfunc`] that
//! either longjmps out, sets a flag, or otherwise avoids the
//! default termination.
//!
//! ## Callback contract
//!
//! NetBSD declares the callback as variadic
//! (`void (*)(int, const char *, ...)`), but this port always
//! pre-formats the diagnostic into a single `%s`-safe message and
//! invokes the callback with the message as the format string and
//! no extra args. Existing C callbacks that simply call `vfprintf`
//! on the format string see the diagnostic verbatim.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::Mutex;

/// FFI type of the error callback. Variadic to match NetBSD's
/// declaration; we never pass extras when invoking, but the type
/// must match for callers casting their `void (*)(int, const char
/// *, ...)` function pointer through this signature.
pub type EFunc = unsafe extern "C" fn(eval: c_int, fmt: *const c_char, ...);

static EFUN_CELL: Mutex<Option<EFunc>> = Mutex::new(None);

/// Write `msg` to stderr followed by a newline, then exit with
/// `eval`. This is the behavior callers see when no custom
/// callback has been installed via [`esetfunc`].
unsafe fn default_efun(eval: c_int, msg: &CStr) {
    let bytes = msg.to_bytes();
    unsafe {
        libc::write(2, bytes.as_ptr() as *const c_void, bytes.len());
        libc::write(2, b"\n".as_ptr() as *const c_void, 1);
        libc::exit(eval);
    }
}

/// Format `msg` (already a CStr) into the registered callback or
/// the default. `eval` is the exit code the default would use.
///
/// If a custom callback is installed and returns normally, this
/// function also returns (so the wrapper can propagate a NULL/0
/// failure indicator to the caller). Only the default callback
/// terminates the process.
unsafe fn report_failure(eval: c_int, msg: &CStr) {
    let installed = { *EFUN_CELL.lock().unwrap() };
    if let Some(efun) = installed {
        unsafe { efun(eval, msg.as_ptr()) };
    } else {
        unsafe { default_efun(eval, msg) };
    }
}

/// NetBSD `esetfunc(efunc)` — install a new global error callback.
/// Returns the previously-installed callback, or NULL if no custom
/// callback was installed (i.e. the default behavior was active).
///
/// # Safety
///
/// `new` (when non-NULL) must be a callable `extern "C"` function
/// pointer that respects the NetBSD efun callback contract.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn esetfunc(new: Option<EFunc>) -> Option<EFunc> {
    let mut cell = EFUN_CELL.lock().unwrap();
    let prev = *cell;
    *cell = new;
    prev
}

/// NetBSD `estrlcpy(dst, src, dstsize)` — `strlcpy` wrapper that
/// reports failure and exits if the source would overflow `dst`.
///
/// # Safety
///
/// `dst` must be valid for `dstsize` writable bytes. `src` must be
/// NUL-terminated.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn estrlcpy(dst: *mut c_char, src: *const c_char, dstsize: usize) -> usize {
    if dst.is_null() || src.is_null() {
        unsafe { report_failure(libc::EXIT_FAILURE, c"estrlcpy: NULL argument") };
        return 0;
    }
    let n = unsafe { crate::string_abi::strlcpy(dst, src, dstsize) };
    if n >= dstsize {
        unsafe {
            report_failure(
                libc::EXIT_FAILURE,
                c"estrlcpy: source overflows destination",
            )
        };
    }
    n
}

/// NetBSD `estrlcat(dst, src, dstsize)` — `strlcat` wrapper that
/// reports failure and exits if the concatenated result would
/// overflow `dst`.
///
/// # Safety
///
/// Same as [`estrlcpy`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn estrlcat(dst: *mut c_char, src: *const c_char, dstsize: usize) -> usize {
    if dst.is_null() || src.is_null() {
        unsafe { report_failure(libc::EXIT_FAILURE, c"estrlcat: NULL argument") };
        return 0;
    }
    let n = unsafe { crate::string_abi::strlcat(dst, src, dstsize) };
    if n >= dstsize {
        unsafe {
            report_failure(
                libc::EXIT_FAILURE,
                c"estrlcat: source overflows destination",
            )
        };
    }
    n
}

/// NetBSD `estrdup(s)` — `strdup` that reports failure and exits
/// when allocation fails. Returned pointer must be released via
/// `free`.
///
/// # Safety
///
/// `s` must be NUL-terminated.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn estrdup(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        unsafe { report_failure(libc::EXIT_FAILURE, c"estrdup: NULL argument") };
        return std::ptr::null_mut();
    }
    let p = unsafe { crate::string_abi::strdup(s) };
    if p.is_null() {
        unsafe { report_failure(libc::EXIT_FAILURE, c"estrdup: out of memory") };
    }
    p
}

/// NetBSD `estrndup(s, maxlen)` — `strndup` that reports failure
/// and exits when allocation fails.
///
/// # Safety
///
/// `s` must be valid for at least `maxlen` readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn estrndup(s: *const c_char, maxlen: usize) -> *mut c_char {
    if s.is_null() {
        unsafe { report_failure(libc::EXIT_FAILURE, c"estrndup: NULL argument") };
        return std::ptr::null_mut();
    }
    let p = unsafe { crate::string_abi::strndup(s, maxlen) };
    if p.is_null() {
        unsafe { report_failure(libc::EXIT_FAILURE, c"estrndup: out of memory") };
    }
    p
}

/// NetBSD `emalloc(size)` — `malloc` that reports failure and exits
/// when allocation fails.
///
/// # Safety
///
/// Returned pointer must be released via `free`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn emalloc(size: usize) -> *mut c_void {
    let p = unsafe { crate::malloc_abi::malloc(size) };
    if p.is_null() && size != 0 {
        unsafe { report_failure(libc::EXIT_FAILURE, c"emalloc: out of memory") };
    }
    p
}

/// NetBSD `ecalloc(nmemb, size)` — `calloc` that reports failure
/// and exits when allocation fails.
///
/// # Safety
///
/// Returned pointer must be released via `free`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ecalloc(nmemb: usize, size: usize) -> *mut c_void {
    let p = unsafe { crate::malloc_abi::calloc(nmemb, size) };
    if p.is_null() && nmemb != 0 && size != 0 {
        unsafe { report_failure(libc::EXIT_FAILURE, c"ecalloc: out of memory") };
    }
    p
}

/// NetBSD `erealloc(ptr, size)` — `realloc` that reports failure
/// and exits when allocation fails.
///
/// # Safety
///
/// `ptr`, when non-NULL, must have been returned by a prior call to
/// our allocator. Returned pointer must be released via `free`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erealloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let p = unsafe { crate::malloc_abi::realloc(ptr, size) };
    if p.is_null() && size != 0 {
        unsafe { report_failure(libc::EXIT_FAILURE, c"erealloc: out of memory") };
    }
    p
}

/// NetBSD `efopen(path, mode)` — `fopen` that reports failure and
/// exits when the open fails.
///
/// # Safety
///
/// Both `path` and `mode` must be NUL-terminated. Returned `FILE *`
/// must be closed with `fclose`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn efopen(path: *const c_char, mode: *const c_char) -> *mut c_void {
    if path.is_null() || mode.is_null() {
        unsafe { report_failure(libc::EXIT_FAILURE, c"efopen: NULL argument") };
        return std::ptr::null_mut();
    }
    let f = unsafe { crate::stdio_abi::fopen(path, mode) };
    if f.is_null() {
        unsafe { report_failure(libc::EXIT_FAILURE, c"efopen: cannot open file") };
    }
    f
}

/// NetBSD `estrtoi(nptr, base, lo, hi)` — bounded signed integer
/// parser that exits on failure. Wraps [`crate::stdlib_abi::strtoi`]
/// and, on any non-success rstatus (`EINVAL`, `ENOTSUP`, `ERANGE`),
/// invokes the global efun callback. The returned value is
/// `strtoi`'s clamped result (or 0 on missing-digits / NULL nptr).
///
/// # Safety
///
/// `nptr` must be NUL-terminated.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn estrtoi(
    nptr: *const c_char,
    base: c_int,
    lo: libc::intmax_t,
    hi: libc::intmax_t,
) -> libc::intmax_t {
    if nptr.is_null() {
        unsafe { report_failure(libc::EXIT_FAILURE, c"estrtoi: NULL argument") };
        return 0;
    }
    let mut rstatus: c_int = 0;
    let v = unsafe {
        crate::stdlib_abi::strtoi(nptr, std::ptr::null_mut(), base, lo, hi, &mut rstatus)
    };
    if rstatus != 0 {
        let msg: &CStr = match rstatus {
            x if x == libc::EINVAL => c"estrtoi: no digits to parse",
            x if x == libc::ENOTSUP => c"estrtoi: invalid base",
            x if x == libc::ERANGE => c"estrtoi: value out of range",
            _ => c"estrtoi: parse failure",
        };
        unsafe { report_failure(libc::EXIT_FAILURE, msg) };
    }
    v
}

/// NetBSD `estrtou(nptr, base, lo, hi)` — bounded unsigned integer
/// parser that exits on failure. Wraps [`crate::stdlib_abi::strtou`]
/// and routes non-success rstatus through the global efun callback.
/// See [`estrtoi`] for the failure-mode contract.
///
/// # Safety
///
/// Same as [`estrtoi`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn estrtou(
    nptr: *const c_char,
    base: c_int,
    lo: libc::uintmax_t,
    hi: libc::uintmax_t,
) -> libc::uintmax_t {
    if nptr.is_null() {
        unsafe { report_failure(libc::EXIT_FAILURE, c"estrtou: NULL argument") };
        return 0;
    }
    let mut rstatus: c_int = 0;
    let v = unsafe {
        crate::stdlib_abi::strtou(nptr, std::ptr::null_mut(), base, lo, hi, &mut rstatus)
    };
    if rstatus != 0 {
        let msg: &CStr = match rstatus {
            x if x == libc::EINVAL => c"estrtou: no digits to parse",
            x if x == libc::ENOTSUP => c"estrtou: invalid base",
            x if x == libc::ERANGE => c"estrtou: value out of range",
            _ => c"estrtou: parse failure",
        };
        unsafe { report_failure(libc::EXIT_FAILURE, msg) };
    }
    v
}

#[cfg(test)]
pub(crate) mod test_helpers {
    //! Internal helpers exposed for the integration tests so they
    //! can flush the global callback to a known state between
    //! tests.
    use super::{EFUN_CELL, EFunc};

    pub fn reset_efun() -> Option<EFunc> {
        let mut cell = EFUN_CELL.lock().unwrap();
        let prev = *cell;
        *cell = None;
        prev
    }
}
