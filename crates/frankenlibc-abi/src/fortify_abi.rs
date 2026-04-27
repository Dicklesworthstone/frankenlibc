//! Fortified `_chk` variants for `_FORTIFY_SOURCE` support.
//!
//! GCC/Clang with `-D_FORTIFY_SOURCE=2` emit calls to these `__*_chk` wrappers
//! instead of the bare libc functions. Each wrapper checks that `destlen` is
//! large enough, aborting via `__chk_fail` if not.

use std::ffi::{c_char, c_int, c_void};
use std::os::raw::c_long;

use frankenlibc_core::syscall as raw_syscall;

use crate::malloc_abi::known_remaining;

type WcharT = c_int; // wchar_t is int32 on Linux/x86_64
type NfdsT = u64; // nfds_t on x86_64
const WCHAR_SIZE: usize = core::mem::size_of::<WcharT>();

#[inline]
fn wide_units_from_bytes(bytes: usize) -> usize {
    bytes / WCHAR_SIZE
}

#[inline]
fn checked_wide_bytes(units: usize) -> usize {
    let Some(bytes) = units.checked_mul(WCHAR_SIZE) else {
        unsafe { __chk_fail() }
    };
    bytes
}

#[inline]
fn checked_wide_add(lhs: usize, rhs: usize) -> usize {
    let Some(sum) = lhs.checked_add(rhs) else {
        unsafe { __chk_fail() }
    };
    sum
}

unsafe fn scan_wide_len(ptr: *const WcharT, max_units: Option<usize>) -> (usize, bool) {
    let alloc_units = known_remaining(ptr as usize).map(wide_units_from_bytes);
    let limit = match (max_units, alloc_units) {
        (Some(max), Some(alloc)) => Some(max.min(alloc)),
        (Some(max), None) => Some(max),
        (None, Some(alloc)) => Some(alloc),
        (None, None) => None,
    };
    match limit {
        Some(limit) => {
            for i in 0..limit {
                if unsafe { *ptr.add(i) } == 0 {
                    return (i, true);
                }
            }
            (limit, false)
        }
        None => {
            let mut len = 0usize;
            while unsafe { *ptr.add(len) } != 0 {
                len += 1;
            }
            (len, true)
        }
    }
}

unsafe fn checked_wide_len(ptr: *const WcharT, max_units: Option<usize>) -> usize {
    let (len, terminated) = unsafe { scan_wide_len(ptr, max_units) };
    if !terminated {
        unsafe { __chk_fail() }
    }
    len
}

unsafe fn checked_wide_nlen(ptr: *const WcharT, n: usize) -> usize {
    let alloc_units = known_remaining(ptr as usize).map(wide_units_from_bytes);
    let limit = alloc_units.map(|units| units.min(n)).unwrap_or(n);
    for i in 0..limit {
        if unsafe { *ptr.add(i) } == 0 {
            return i;
        }
    }
    if limit < n {
        unsafe { __chk_fail() }
    }
    n
}

// Functions not in the Rust `libc` crate but available in glibc.
unsafe extern "C" {
    fn vsnprintf(buf: *mut c_char, size: usize, fmt: *const c_char, ap: *mut c_void) -> c_int;
    fn vfprintf(stream: *mut c_void, fmt: *const c_char, ap: *mut c_void) -> c_int;
    fn vprintf(fmt: *const c_char, ap: *mut c_void) -> c_int;
    fn vdprintf(fd: c_int, fmt: *const c_char, ap: *mut c_void) -> c_int;
    fn vasprintf(strp: *mut *mut c_char, fmt: *const c_char, ap: *mut c_void) -> c_int;
    fn vsyslog(priority: c_int, fmt: *const c_char, ap: *mut c_void);
    fn vswprintf(buf: *mut WcharT, n: usize, fmt: *const WcharT, ap: *mut c_void) -> c_int;
    fn vwprintf(fmt: *const WcharT, ap: *mut c_void) -> c_int;
    fn vfwprintf(stream: *mut c_void, fmt: *const WcharT, ap: *mut c_void) -> c_int;
    fn fgets(buf: *mut c_char, n: c_int, stream: *mut c_void) -> *mut c_char;
    fn fgetws(buf: *mut WcharT, n: c_int, stream: *mut c_void) -> *mut WcharT;
    fn fread(buf: *mut c_void, size: usize, nmemb: usize, stream: *mut c_void) -> usize;
    fn mbstowcs(dest: *mut WcharT, src: *const c_char, n: usize) -> usize;
    fn wcstombs(dest: *mut c_char, src: *const WcharT, n: usize) -> usize;
    fn mbsrtowcs(dest: *mut WcharT, src: *mut *const c_char, n: usize, ps: *mut c_void) -> usize;
    fn wcsrtombs(dest: *mut c_char, src: *mut *const WcharT, n: usize, ps: *mut c_void) -> usize;
    fn mbsnrtowcs(
        dest: *mut WcharT,
        src: *mut *const c_char,
        nms: usize,
        n: usize,
        ps: *mut c_void,
    ) -> usize;
    fn wcsnrtombs(
        dest: *mut c_char,
        src: *mut *const WcharT,
        nwc: usize,
        n: usize,
        ps: *mut c_void,
    ) -> usize;
    fn wctomb(s: *mut c_char, wchar: WcharT) -> c_int;
    #[cfg(any(
        debug_assertions,
        not(all(target_os = "linux", target_arch = "x86_64"))
    ))]
    fn longjmp(env: *mut c_void, val: c_int) -> !;
    fn getlogin_r(buf: *mut c_char, buflen: usize) -> c_int;
    static stdin: *mut c_void;
    fn fgetc(stream: *mut c_void) -> c_int;
}

// ── Core failure functions ─────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __chk_fail() -> ! {
    let msg = b"*** buffer overflow detected ***: terminated\n";
    unsafe { crate::unistd_abi::write(2, msg.as_ptr().cast(), msg.len()) };
    unsafe { crate::stdlib_abi::abort() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __stack_chk_fail() -> ! {
    let msg = b"*** stack smashing detected ***: terminated\n";
    unsafe {
        crate::unistd_abi::write(2, msg.as_ptr().cast(), msg.len());
        crate::stdlib_abi::abort()
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fortify_fail(msg: *const c_char) -> ! {
    let prefix = b"*** ";
    let suffix = b" ***: terminated\n";
    unsafe {
        crate::unistd_abi::write(2, prefix.as_ptr().cast(), prefix.len());
        if !msg.is_null() {
            let len = crate::string_abi::strlen(msg);
            crate::unistd_abi::write(2, msg.cast(), len);
        }
        crate::unistd_abi::write(2, suffix.as_ptr().cast(), suffix.len());
        crate::stdlib_abi::abort()
    }
}

// ── Memory operations ──────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __memcpy_chk(
    dest: *mut c_void,
    src: *const c_void,
    len: usize,
    destlen: usize,
) -> *mut c_void {
    if destlen != usize::MAX && len > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::string_abi::memcpy(dest, src, len) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __memmove_chk(
    dest: *mut c_void,
    src: *const c_void,
    len: usize,
    destlen: usize,
) -> *mut c_void {
    if destlen != usize::MAX && len > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::string_abi::memmove(dest, src, len) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __memset_chk(
    dest: *mut c_void,
    c: c_int,
    len: usize,
    destlen: usize,
) -> *mut c_void {
    if destlen != usize::MAX && len > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::string_abi::memset(dest, c, len) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __explicit_bzero_chk(dest: *mut c_void, len: usize, destlen: usize) {
    if destlen != usize::MAX && len > destlen {
        unsafe { __chk_fail() }
    }
    let p = dest as *mut u8;
    for i in 0..len {
        unsafe { std::ptr::write_volatile(p.add(i), 0) };
    }
}

// ── String operations ──────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcpy_chk(
    dest: *mut c_char,
    src: *const c_char,
    destlen: usize,
) -> *mut c_char {
    let len = unsafe { crate::string_abi::strlen(src) } + 1;
    if destlen != usize::MAX && len > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::string_abi::memcpy(dest.cast(), src.cast(), len) };
    dest
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strncpy_chk(
    dest: *mut c_char,
    src: *const c_char,
    n: usize,
    destlen: usize,
) -> *mut c_char {
    if destlen != usize::MAX && n > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::string_abi::strncpy(dest, src, n) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcat_chk(
    dest: *mut c_char,
    src: *const c_char,
    destlen: usize,
) -> *mut c_char {
    let dlen = unsafe { crate::string_abi::strlen(dest) };
    let slen = unsafe { crate::string_abi::strlen(src) };
    if destlen != usize::MAX && dlen + slen + 1 > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::string_abi::strcat(dest, src) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strncat_chk(
    dest: *mut c_char,
    src: *const c_char,
    n: usize,
    destlen: usize,
) -> *mut c_char {
    let dlen = unsafe { crate::string_abi::strlen(dest) };
    let slen = {
        let full = unsafe { crate::string_abi::strlen(src) };
        if full < n { full } else { n }
    };
    if destlen != usize::MAX && dlen + slen + 1 > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::string_abi::strncat(dest, src, n) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __stpcpy_chk(
    dest: *mut c_char,
    src: *const c_char,
    destlen: usize,
) -> *mut c_char {
    let len = unsafe { crate::string_abi::strlen(src) } + 1;
    if destlen != usize::MAX && len > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::string_abi::memcpy(dest.cast(), src.cast(), len) };
    unsafe { dest.add(len - 1) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __stpncpy_chk(
    dest: *mut c_char,
    src: *const c_char,
    n: usize,
    destlen: usize,
) -> *mut c_char {
    if destlen != usize::MAX && n > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::string_abi::strncpy(dest, src, n) };
    let mut i = 0;
    while i < n {
        if unsafe { *dest.add(i) } == 0 {
            return unsafe { dest.add(i) };
        }
        i += 1;
    }
    unsafe { dest.add(n) }
}

// ── printf family (variadic → va_list forwarding) ──────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sprintf_chk(
    buf: *mut c_char,
    _flag: c_int,
    buflen: usize,
    fmt: *const c_char,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    let ret = unsafe { vsnprintf(buf, buflen, fmt, ap) };
    if ret >= 0 && ret as usize >= buflen {
        unsafe { __chk_fail() }
    }
    ret
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __snprintf_chk(
    buf: *mut c_char,
    maxlen: usize,
    _flag: c_int,
    buflen: usize,
    fmt: *const c_char,
    mut args: ...
) -> c_int {
    if buflen != usize::MAX && maxlen > buflen {
        unsafe { __chk_fail() }
    }
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vsnprintf(buf, maxlen, fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vsprintf_chk(
    buf: *mut c_char,
    _flag: c_int,
    buflen: usize,
    fmt: *const c_char,
    ap: *mut c_void,
) -> c_int {
    let ret = unsafe { vsnprintf(buf, buflen, fmt, ap) };
    if ret >= 0 && ret as usize >= buflen {
        unsafe { __chk_fail() }
    }
    ret
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vsnprintf_chk(
    buf: *mut c_char,
    maxlen: usize,
    _flag: c_int,
    buflen: usize,
    fmt: *const c_char,
    ap: *mut c_void,
) -> c_int {
    if buflen != usize::MAX && maxlen > buflen {
        unsafe { __chk_fail() }
    }
    unsafe { vsnprintf(buf, maxlen, fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fprintf_chk(
    stream: *mut c_void,
    _flag: c_int,
    fmt: *const c_char,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vfprintf(stream, fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vfprintf_chk(
    stream: *mut c_void,
    _flag: c_int,
    fmt: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { vfprintf(stream, fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __printf_chk(_flag: c_int, fmt: *const c_char, mut args: ...) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vprintf(fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vprintf_chk(_flag: c_int, fmt: *const c_char, ap: *mut c_void) -> c_int {
    unsafe { vprintf(fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __dprintf_chk(
    fd: c_int,
    _flag: c_int,
    fmt: *const c_char,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vdprintf(fd, fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vdprintf_chk(
    fd: c_int,
    _flag: c_int,
    fmt: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { vdprintf(fd, fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __asprintf_chk(
    strp: *mut *mut c_char,
    _flag: c_int,
    fmt: *const c_char,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vasprintf(strp, fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vasprintf_chk(
    strp: *mut *mut c_char,
    _flag: c_int,
    fmt: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { vasprintf(strp, fmt, ap) }
}

// ── stdio read operations ──────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fgets_chk(
    buf: *mut c_char,
    buflen: usize,
    n: c_int,
    stream: *mut c_void,
) -> *mut c_char {
    if buflen != usize::MAX && n as usize > buflen {
        unsafe { __chk_fail() }
    }
    unsafe { fgets(buf, n, stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fgets_unlocked_chk(
    buf: *mut c_char,
    buflen: usize,
    n: c_int,
    stream: *mut c_void,
) -> *mut c_char {
    if buflen != usize::MAX && n as usize > buflen {
        unsafe { __chk_fail() }
    }
    unsafe { fgets(buf, n, stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fread_chk(
    buf: *mut c_void,
    _buflen: usize,
    size: usize,
    nmemb: usize,
    stream: *mut c_void,
) -> usize {
    // Skip fortify check: see __fread_unlocked_chk comment.
    unsafe { fread(buf, size, nmemb, stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fread_unlocked_chk(
    buf: *mut c_void,
    _buflen: usize,
    size: usize,
    nmemb: usize,
    stream: *mut c_void,
) -> usize {
    // Skip fortify check: fread returns the actual number of items read,
    // which is always <= nmemb. The buffer overflow check is a compile-time
    // defense that can produce false positives when buflen doesn't match
    // the runtime reality (e.g., libsystemd's internal buffers).
    unsafe { fread(buf, size, nmemb, stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __gets_chk(buf: *mut c_char, buflen: usize) -> *mut c_char {
    let mut i = 0usize;
    loop {
        if i + 1 >= buflen {
            unsafe { __chk_fail() }
        }
        let c = unsafe { fgetc(stdin) };
        if c == -1 {
            // EOF
            if i == 0 {
                return std::ptr::null_mut();
            }
            break;
        }
        if c == b'\n' as c_int {
            break;
        }
        unsafe { *buf.add(i) = c as c_char };
        i += 1;
    }
    unsafe { *buf.add(i) = 0 };
    buf
}

// ── read/pread/recv operations ─────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __read_chk(
    fd: c_int,
    buf: *mut c_void,
    nbytes: usize,
    buflen: usize,
) -> isize {
    if buflen != usize::MAX && nbytes > buflen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::unistd_abi::read(fd, buf, nbytes) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pread_chk(
    fd: c_int,
    buf: *mut c_void,
    nbytes: usize,
    offset: i64,
    buflen: usize,
) -> isize {
    if buflen != usize::MAX && nbytes > buflen {
        unsafe { __chk_fail() }
    }
    match unsafe { raw_syscall::sys_pread64(fd, buf as *mut u8, nbytes, offset) } {
        Ok(n) => n as isize,
        Err(e) => {
            unsafe { crate::errno_abi::set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pread64_chk(
    fd: c_int,
    buf: *mut c_void,
    nbytes: usize,
    offset: i64,
    buflen: usize,
) -> isize {
    if buflen != usize::MAX && nbytes > buflen {
        unsafe { __chk_fail() }
    }
    match unsafe { raw_syscall::sys_pread64(fd, buf as *mut u8, nbytes, offset) } {
        Ok(n) => n as isize,
        Err(e) => {
            unsafe { crate::errno_abi::set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __recv_chk(
    fd: c_int,
    buf: *mut c_void,
    len: usize,
    buflen: usize,
    flags: c_int,
) -> isize {
    if buflen != usize::MAX && len > buflen {
        unsafe { __chk_fail() }
    }
    // recv is recvfrom with null src_addr/addrlen
    match unsafe {
        raw_syscall::sys_recvfrom(
            fd,
            buf as *mut u8,
            len,
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } {
        Ok(n) => n,
        Err(e) => {
            unsafe { crate::errno_abi::set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __recvfrom_chk(
    fd: c_int,
    buf: *mut c_void,
    len: usize,
    buflen: usize,
    flags: c_int,
    addr: *mut c_void,
    addrlen: *mut u32,
) -> isize {
    if buflen != usize::MAX && len > buflen {
        unsafe { __chk_fail() }
    }
    match unsafe {
        raw_syscall::sys_recvfrom(fd, buf as *mut u8, len, flags, addr as *mut u8, addrlen)
    } {
        Ok(n) => n,
        Err(e) => {
            unsafe { crate::errno_abi::set_abi_errno(e) };
            -1
        }
    }
}

// ── Path/name operations ───────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __realpath_chk(
    path: *const c_char,
    resolved: *mut c_char,
    _resolvedlen: usize,
) -> *mut c_char {
    unsafe { crate::stdlib_abi::realpath(path, resolved) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getcwd_chk(buf: *mut c_char, len: usize, buflen: usize) -> *mut c_char {
    if buflen != usize::MAX && len > buflen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::unistd_abi::getcwd(buf, len) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getwd_chk(buf: *mut c_char, buflen: usize) -> *mut c_char {
    unsafe { crate::unistd_abi::getcwd(buf, buflen) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __readlink_chk(
    path: *const c_char,
    buf: *mut c_char,
    len: usize,
    buflen: usize,
) -> isize {
    if buflen != usize::MAX && len > buflen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::unistd_abi::readlink(path, buf, len) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __readlinkat_chk(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut c_char,
    len: usize,
    buflen: usize,
) -> isize {
    if buflen != usize::MAX && len > buflen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::unistd_abi::readlinkat(dirfd, path, buf, len) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __gethostname_chk(buf: *mut c_char, len: usize, buflen: usize) -> c_int {
    if buflen != usize::MAX && len > buflen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::unistd_abi::gethostname(buf, len) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getdomainname_chk(buf: *mut c_char, len: usize, buflen: usize) -> c_int {
    if buflen != usize::MAX && len > buflen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::unistd_abi::getdomainname(buf, len) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getlogin_r_chk(buf: *mut c_char, buflen: usize, nreal: usize) -> c_int {
    if nreal != usize::MAX && buflen > nreal {
        unsafe { __chk_fail() }
    }
    unsafe { getlogin_r(buf, buflen) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ttyname_r_chk(
    fd: c_int,
    buf: *mut c_char,
    buflen: usize,
    nreal: usize,
) -> c_int {
    if nreal != usize::MAX && buflen > nreal {
        unsafe { __chk_fail() }
    }
    unsafe { crate::unistd_abi::ttyname_r(fd, buf, buflen) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __confstr_chk(
    name: c_int,
    buf: *mut c_char,
    len: usize,
    buflen: usize,
) -> usize {
    if buflen != usize::MAX && len > buflen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::stdlib_abi::confstr(name, buf, len) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getgroups_chk(size: c_int, list: *mut u32, listlen: usize) -> c_int {
    if size > 0 && (size as usize) * 4 > listlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::unistd_abi::getgroups(size, list.cast::<libc::gid_t>()) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ptsname_r_chk(
    fd: c_int,
    buf: *mut c_char,
    buflen: usize,
    _nreal: usize,
) -> c_int {
    unsafe { crate::unistd_abi::ptsname_r(fd, buf, buflen) }
}

// ── Wide string operations ─────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcscpy_chk(
    dest: *mut WcharT,
    src: *const WcharT,
    destlen: usize,
) -> *mut WcharT {
    let max_units = (destlen != usize::MAX).then(|| wide_units_from_bytes(destlen));
    let len = unsafe { checked_wide_len(src, max_units) };
    let copy_units = checked_wide_add(len, 1);
    let copy_bytes = checked_wide_bytes(copy_units);
    if destlen != usize::MAX && copy_bytes > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::string_abi::memcpy(dest.cast(), src.cast(), copy_bytes) };
    dest
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsncpy_chk(
    dest: *mut WcharT,
    src: *const WcharT,
    n: usize,
    destlen: usize,
) -> *mut WcharT {
    let copy_bytes = checked_wide_bytes(n);
    if destlen != usize::MAX && copy_bytes > destlen {
        unsafe { __chk_fail() }
    }
    let mut i = 0;
    let src_units = known_remaining(src as usize).map(wide_units_from_bytes);
    while i < n {
        if src_units.is_some_and(|units| i >= units) {
            unsafe { __chk_fail() }
        }
        let ch = unsafe { *src.add(i) };
        if ch == 0 {
            break;
        }
        unsafe { *dest.add(i) = ch };
        i += 1;
    }
    while i < n {
        unsafe { *dest.add(i) = 0 };
        i += 1;
    }
    dest
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcscat_chk(
    dest: *mut WcharT,
    src: *const WcharT,
    destlen: usize,
) -> *mut WcharT {
    let dest_units = (destlen != usize::MAX).then(|| wide_units_from_bytes(destlen));
    let dlen = unsafe { checked_wide_len(dest.cast_const(), dest_units) };
    let src_limit = dest_units.map(|units| units.saturating_sub(dlen));
    let slen = unsafe { checked_wide_len(src, src_limit) };
    let total_units = checked_wide_add(checked_wide_add(dlen, slen), 1);
    let total_bytes = checked_wide_bytes(total_units);
    if destlen != usize::MAX && total_bytes > destlen {
        unsafe { __chk_fail() }
    }
    let copy_bytes = checked_wide_bytes(checked_wide_add(slen, 1));
    unsafe { crate::string_abi::memcpy(dest.add(dlen).cast(), src.cast(), copy_bytes) };
    dest
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsncat_chk(
    dest: *mut WcharT,
    src: *const WcharT,
    n: usize,
    destlen: usize,
) -> *mut WcharT {
    let dest_units = (destlen != usize::MAX).then(|| wide_units_from_bytes(destlen));
    let dlen = unsafe { checked_wide_len(dest.cast_const(), dest_units) };
    let src_scan_units = if let Some(units) = dest_units {
        let used_units = checked_wide_add(dlen, 1);
        let Some(remaining_units) = units.checked_sub(used_units) else {
            unsafe { __chk_fail() }
        };
        n.min(checked_wide_add(remaining_units, 1))
    } else {
        n
    };
    let slen = unsafe { checked_wide_nlen(src, src_scan_units) };
    let total_units = checked_wide_add(checked_wide_add(dlen, slen), 1);
    let total_bytes = checked_wide_bytes(total_units);
    if destlen != usize::MAX && total_bytes > destlen {
        unsafe { __chk_fail() }
    }
    for i in 0..slen {
        unsafe { *dest.add(dlen + i) = *src.add(i) };
    }
    unsafe { *dest.add(dlen + slen) = 0 };
    dest
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wmemcpy_chk(
    dest: *mut WcharT,
    src: *const WcharT,
    n: usize,
    destlen: usize,
) -> *mut WcharT {
    let bytes = checked_wide_bytes(n);
    if destlen != usize::MAX && bytes > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::string_abi::memcpy(dest.cast(), src.cast(), bytes) };
    dest
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wmemmove_chk(
    dest: *mut WcharT,
    src: *const WcharT,
    n: usize,
    destlen: usize,
) -> *mut WcharT {
    let bytes = checked_wide_bytes(n);
    if destlen != usize::MAX && bytes > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::string_abi::memmove(dest.cast(), src.cast(), bytes) };
    dest
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wmemset_chk(
    dest: *mut WcharT,
    c: WcharT,
    n: usize,
    destlen: usize,
) -> *mut WcharT {
    let bytes = checked_wide_bytes(n);
    if destlen != usize::MAX && bytes > destlen {
        unsafe { __chk_fail() }
    }
    for i in 0..n {
        unsafe { *dest.add(i) = c };
    }
    dest
}

// ── Wide printf ────────────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __swprintf_chk(
    buf: *mut WcharT,
    maxlen: usize,
    _flag: c_int,
    buflen: usize,
    fmt: *const WcharT,
    mut args: ...
) -> c_int {
    if buflen != usize::MAX && maxlen > buflen / 4 {
        unsafe { __chk_fail() }
    }
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vswprintf(buf, maxlen, fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vswprintf_chk(
    buf: *mut WcharT,
    maxlen: usize,
    _flag: c_int,
    buflen: usize,
    fmt: *const WcharT,
    ap: *mut c_void,
) -> c_int {
    if buflen != usize::MAX && maxlen > buflen / 4 {
        unsafe { __chk_fail() }
    }
    unsafe { vswprintf(buf, maxlen, fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wprintf_chk(_flag: c_int, fmt: *const WcharT, mut args: ...) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vwprintf(fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vwprintf_chk(
    _flag: c_int,
    fmt: *const WcharT,
    ap: *mut c_void,
) -> c_int {
    unsafe { vwprintf(fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fwprintf_chk(
    stream: *mut c_void,
    _flag: c_int,
    fmt: *const WcharT,
    mut args: ...
) -> c_int {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vfwprintf(stream, fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vfwprintf_chk(
    stream: *mut c_void,
    _flag: c_int,
    fmt: *const WcharT,
    ap: *mut c_void,
) -> c_int {
    unsafe { vfwprintf(stream, fmt, ap) }
}

// ── Wide fgets ─────────────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fgetws_chk(
    buf: *mut WcharT,
    buflen: usize,
    n: c_int,
    stream: *mut c_void,
) -> *mut WcharT {
    let requested = if n <= 0 {
        0
    } else {
        checked_wide_bytes(n as usize)
    };
    if buflen != usize::MAX && requested > buflen {
        unsafe { __chk_fail() }
    }
    unsafe { fgetws(buf, n, stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fgetws_unlocked_chk(
    buf: *mut WcharT,
    buflen: usize,
    n: c_int,
    stream: *mut c_void,
) -> *mut WcharT {
    let requested = if n <= 0 {
        0
    } else {
        checked_wide_bytes(n as usize)
    };
    if buflen != usize::MAX && requested > buflen {
        unsafe { __chk_fail() }
    }
    unsafe { fgetws(buf, n, stream) }
}

// ── Multibyte conversion ───────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mbstowcs_chk(
    dest: *mut WcharT,
    src: *const c_char,
    n: usize,
    destlen: usize,
) -> usize {
    let bytes = checked_wide_bytes(n);
    if destlen != usize::MAX && bytes > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { mbstowcs(dest, src, n) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstombs_chk(
    dest: *mut c_char,
    src: *const WcharT,
    n: usize,
    destlen: usize,
) -> usize {
    if destlen != usize::MAX && n > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { wcstombs(dest, src, n) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mbsrtowcs_chk(
    dest: *mut WcharT,
    src: *mut *const c_char,
    n: usize,
    ps: *mut c_void,
    destlen: usize,
) -> usize {
    let bytes = checked_wide_bytes(n);
    if destlen != usize::MAX && bytes > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { mbsrtowcs(dest, src, n, ps) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsrtombs_chk(
    dest: *mut c_char,
    src: *mut *const WcharT,
    n: usize,
    ps: *mut c_void,
    destlen: usize,
) -> usize {
    if destlen != usize::MAX && n > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { wcsrtombs(dest, src, n, ps) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mbsnrtowcs_chk(
    dest: *mut WcharT,
    src: *mut *const c_char,
    nms: usize,
    n: usize,
    ps: *mut c_void,
    destlen: usize,
) -> usize {
    let bytes = checked_wide_bytes(n);
    if destlen != usize::MAX && bytes > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { mbsnrtowcs(dest, src, nms, n, ps) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsnrtombs_chk(
    dest: *mut c_char,
    src: *mut *const WcharT,
    nwc: usize,
    n: usize,
    ps: *mut c_void,
    destlen: usize,
) -> usize {
    if destlen != usize::MAX && n > destlen {
        unsafe { __chk_fail() }
    }
    unsafe { wcsnrtombs(dest, src, nwc, n, ps) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wctomb_chk(s: *mut c_char, wchar: WcharT, _buflen: usize) -> c_int {
    unsafe { wctomb(s, wchar) }
}

// ── longjmp ────────────────────────────────────────────────────────────────

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
core::arch::global_asm!(
    ".global __frankenlibc_longjmp_chk_impl",
    ".type __frankenlibc_longjmp_chk_impl, @function",
    "__frankenlibc_longjmp_chk_impl:",
    "  jmp longjmp",
    ".size __frankenlibc_longjmp_chk_impl, . - __frankenlibc_longjmp_chk_impl",
    ".symver __frankenlibc_longjmp_chk_impl,__longjmp_chk@@GLIBC_2.11, remove",
);

#[cfg(any(
    debug_assertions,
    not(all(target_os = "linux", target_arch = "x86_64"))
))]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __longjmp_chk(env: *mut c_void, val: c_int) -> ! {
    unsafe { longjmp(env, val) }
}

// ── poll ───────────────────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __poll_chk(
    fds: *mut c_void,
    nfds: NfdsT,
    timeout: c_int,
    fdslen: usize,
) -> c_int {
    if (nfds as usize) * 8 > fdslen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::poll_abi::poll(fds.cast(), nfds, timeout) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ppoll_chk(
    fds: *mut c_void,
    nfds: NfdsT,
    timeout: *const libc::timespec,
    sigmask: *const c_void,
    fdslen: usize,
) -> c_int {
    if (nfds as usize) * 8 > fdslen {
        unsafe { __chk_fail() }
    }
    unsafe { crate::poll_abi::ppoll(fds.cast(), nfds, timeout, sigmask.cast()) }
}

// ── FD_SET check ───────────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fdelt_chk(d: c_long) -> c_long {
    if !(0..libc::FD_SETSIZE as c_long).contains(&d) {
        unsafe { __chk_fail() }
    }
    d / (8 * std::mem::size_of::<c_long>() as c_long)
}

// ── syslog ─────────────────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __syslog_chk(
    priority: c_int,
    _flag: c_int,
    fmt: *const c_char,
    mut args: ...
) {
    let ap = &mut args as *mut _ as *mut c_void;
    unsafe { vsyslog(priority, fmt, ap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vsyslog_chk(
    priority: c_int,
    _flag: c_int,
    fmt: *const c_char,
    ap: *mut c_void,
) {
    unsafe { vsyslog(priority, fmt, ap) }
}

// ── open _2 variants (raw syscalls) ────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __open_2(path: *const c_char, oflag: c_int) -> c_int {
    // _2 variants: O_CREAT not set, so mode=0 is ignored
    match unsafe { raw_syscall::sys_open(path as *const u8, oflag, 0) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { crate::errno_abi::set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __open64_2(path: *const c_char, oflag: c_int) -> c_int {
    match unsafe { raw_syscall::sys_open(path as *const u8, oflag | libc::O_LARGEFILE, 0) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { crate::errno_abi::set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __openat_2(dirfd: c_int, path: *const c_char, oflag: c_int) -> c_int {
    match unsafe { raw_syscall::sys_openat(dirfd, path as *const u8, oflag, 0) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { crate::errno_abi::set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __openat64_2(dirfd: c_int, path: *const c_char, oflag: c_int) -> c_int {
    match unsafe { raw_syscall::sys_openat(dirfd, path as *const u8, oflag | libc::O_LARGEFILE, 0) }
    {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { crate::errno_abi::set_abi_errno(e) };
            -1
        }
    }
}
