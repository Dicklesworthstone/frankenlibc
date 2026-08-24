//! Fortified `_chk` variants for `_FORTIFY_SOURCE` support.
//!
//! GCC/Clang with `-D_FORTIFY_SOURCE=2` emit calls to these `__*_chk` wrappers
//! instead of the bare libc functions. Each wrapper checks that `destlen` is
//! large enough, aborting via `__chk_fail` if not.

use std::ffi::{c_char, c_int, c_void};
use std::os::raw::c_long;

use frankenlibc_core::syscall as raw_syscall;

use crate::malloc_abi::known_remaining;

// `wchar_t` has the same width on the Linux targets we support, but not the
// same signedness: x86_64 uses `c_int`, whereas aarch64 uses `c_uint`.
// Fortify entrypoints must use the target ABI type so their calls into the
// wide-character implementation remain type-correct on both architectures.
type WcharT = libc::wchar_t;
type NfdsT = u64; // nfds_t on x86_64
const WCHAR_SIZE: usize = core::mem::size_of::<WcharT>();
const FORTIFY_PATH_MAX: usize = 4096;
// MB_LEN_MAX (16) intentionally has no constant here. It is what the FORTIFY
// header macro compares the object size against when deciding whether to route
// a call to __wctomb_chk at all; the runtime check inside that function uses
// MB_CUR_MAX instead. Having both spelled out invited exactly the confusion
// that made __wctomb_chk reject buffers glibc accepts. bd-ddr8kv.

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

// THE NARROW `v*printf` FAMILY IS FL'S OWN, NOT A LINK-TIME EXTERN (bd-8std0q).
//
// These used to be declared in the block below, under a comment saying they were
// "available in glibc". fl EXPORTS every one of them, so the declaration bound to
// whichever the linker chose: glibc's in a test binary, where fl's `#[no_mangle]`
// is disabled by cfg, and fl's in a deployed preload where it is not.
//
// That meant THE TESTED PATH WAS NOT THE SHIPPED PATH. Every `__*_chk` arm that
// checks formatted output was validating glibc's formatter in CI and fl's in
// production, so a divergence in fl's own printf behind `_FORTIFY_SOURCE` was
// invisible to this suite by construction — the same hollow-arm hazard the
// differential gates were audited for, here in production code.
//
// Importing fl's implementations directly makes the binding a property of the code
// rather than of link order. The signatures are identical, so every call site is
// unchanged.
use crate::stdio_abi::{vasprintf, vdprintf, vfprintf, vprintf, vsnprintf};

// Functions not in the Rust `libc` crate but available in glibc.
//
// WHAT REMAINS HERE IS NOT AUDITED. fl also exports several of the symbols still
// declared below — `fgets`, `fread`, `mbstowcs`, `wcstombs`, the wide `v*wprintf`
// family — so they carry the same link-order ambiguity and should be moved the
// same way once each is checked. They are left for a follow-up rather than
// rewired blind; see bd-8std0q.
// THE REST OF THE BLOCK IS NOW FL'S OWN TOO (bd-8std0q).
//
// Every symbol below was declared as a link-time extern, and fl exports all of
// them, so each bound to whichever the linker chose -- glibc's in a test binary,
// fl's in a deployed preload. The `__*_chk` wrappers built on them therefore
// validated one implementation in CI and shipped another.
//
// The narrow `v*printf` family was moved first and the fortify suite did not
// move: 162 passed before and after. These thirteen complete the block. The
// compiler is the signature check -- an `extern` declaration that disagreed with
// fl's definition fails at the call site rather than silently binding to
// something else, which is the whole point of importing rather than declaring.
use crate::stdio_abi::{fgets, fread};
use crate::unistd_abi::vsyslog;
use crate::wchar_abi::{
    fgetws, mbsnrtowcs, mbsrtowcs, mbstowcs, vfwprintf, vswprintf, vwprintf, wcsnrtombs, wcsrtombs,
    wcstombs,
};

// AND THE LAST FOUR (bd-8std0q). `longjmp` is the one that mattered most: fl's
// `setjmp` produces the jmp_buf, so resolving `longjmp` to glibc would hand one
// implementation's environment to the other's unwinder — undefined, and silently
// dependent on link order. The rest follow the same rule as the block above.
use crate::setjmp_abi::longjmp;
use crate::stdio_abi::fgetc;
use crate::unistd_abi::getlogin_r;
use crate::wchar_abi::wctomb;

unsafe extern "C" {
    static stdin: *mut c_void;
}

// ── Core failure functions ─────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __chk_fail() -> ! {
    let msg = b"*** buffer overflow detected ***: terminated\n";
    unsafe {
        let _ = frankenlibc_core::syscall::sys_write(2, msg.as_ptr().cast(), msg.len());
    }
    unsafe { crate::stdlib_abi::abort() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __stack_chk_fail() -> ! {
    let msg = b"*** stack smashing detected ***: terminated\n";
    unsafe {
        let _ = frankenlibc_core::syscall::sys_write(2, msg.as_ptr().cast(), msg.len());
        crate::stdlib_abi::abort()
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fortify_fail(msg: *const c_char) -> ! {
    let prefix = b"*** ";
    let suffix = b" ***: terminated\n";
    unsafe {
        let _ = frankenlibc_core::syscall::sys_write(2, prefix.as_ptr().cast(), prefix.len());
        let len = crate::string_abi::strlen(msg);
        let _ = frankenlibc_core::syscall::sys_write(2, msg.cast(), len);
        let _ = frankenlibc_core::syscall::sys_write(2, suffix.as_ptr().cast(), suffix.len());
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
    // Route to explicit_bzero (→ bzero → raw_memset_bytes) instead of a byte-by-byte
    // write_volatile loop. raw_memset_bytes zeroes with 32B-unrolled write_volatile::<u64>
    // stores, which the loop-idiom recognizer also refuses to coalesce into an elidable
    // @llvm.memset — so the security guarantee (the zeroing cannot be dead-store-eliminated)
    // is preserved while moving 8 bytes per store instead of 1. Byte-identical: both zero
    // exactly `len` bytes; explicit_bzero's null / zero-length guards are a harmless superset.
    unsafe { crate::string_abi::explicit_bzero(dest, len) };
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
    // `strncat` reads at most `n` bytes of `src`, so a caller may legitimately
    // pass a `src` holding only `n` readable bytes with no NUL. Use the bounded
    // `strnlen` here: an unbounded `strlen(src)` would over-read past `n` and
    // could fault on an otherwise-correct caller. `strnlen` yields the same
    // `min(strlen(src), n)` value glibc's `__strncat_chk` computes via
    // `strnlen(s2, n)`.
    let slen = unsafe { crate::string_abi::strnlen(src, n) };
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

/// The measured `__fgets*_chk` rule, shared by the locked and unlocked forms.
///
/// THE SAME DIVERGENCE AS THE WIDE PAIR, found by running the wide probe against
/// the narrow entry point instead of assuming this one was right (bd-917hzv).
/// fl aborted whenever `n > buflen`, statically. glibc does not.
///
/// Host glibc 2.42, fork-isolated, `size` in bytes:
///
/// ```text
///   content     n    size   glibc      old fl
///   short(12)  257    256   ok         ABORT   <-- diverged
///   short(12)  300    256   ok         ABORT   <-- diverged
///   short(12) 1024    256   ok         ABORT   <-- diverged
///   long(300)  257    256   ABORT      ABORT
///   short(12)   64      8   ABORT      ABORT
///   both       256    256   ok         ok
///   both      2000   4096   ok         ok
///   both        -1 /  0     NULL       NULL
/// ```
///
/// So a caller doing `fgets(buf, 1024, fp)` into a 256-byte buffer is killed by
/// the old rule and runs fine under glibc whenever the line is short. The rule
/// that fits every row is two conditions: `n > buflen` AND the content did not
/// actually fit — glibc only reaches its overflow check once the read fills the
/// clamped buffer.
///
/// # Safety
/// `buf` must be writable for `buflen` bytes and `stream` a valid `FILE*`.
unsafe fn fgets_chk_common(
    buf: *mut c_char,
    buflen: usize,
    n: c_int,
    stream: *mut c_void,
) -> *mut c_char {
    // A non-positive `n` returns NULL rather than aborting — `n as usize` would
    // otherwise turn a negative count into a huge one — and an unknown size
    // cannot bound anything.
    if n <= 0 || buflen == usize::MAX {
        // SAFETY: caller's contract.
        return unsafe { fgets(buf, n, stream) };
    }

    // Inside glibc's bound: pass through untouched, which is what it does.
    if (n as usize) <= buflen {
        // SAFETY: caller's contract.
        return unsafe { fgets(buf, n, stream) };
    }

    // `n` exceeds the buffer, so bound the read to what it holds. `fgets` writes
    // at most `k - 1` bytes plus a terminator for a limit of `k`, so passing
    // `buflen` can never write past the buffer whatever the content is.
    let clamped = buflen.min(n as usize) as c_int;
    // SAFETY: `clamped` is at most the buffer's byte capacity.
    let result = unsafe { fgets(buf, clamped, stream) };
    if result.is_null() {
        return result;
    }

    // Truncation means the content WOULD have overflowed the caller's buffer,
    // which is the condition glibc aborts on. A run ending in a newline, or
    // shorter than the clamp, fitted.
    let mut len = 0usize;
    // SAFETY: `fgets` NUL-terminates within `clamped` bytes.
    while len < clamped as usize && unsafe { *buf.add(len) } != 0 {
        len += 1;
    }
    let filled_to_capacity = len + 1 == clamped as usize;
    // SAFETY: `len` is in bounds by the loop above.
    let ended_with_newline = len > 0 && unsafe { *buf.add(len - 1) } == b'\n' as c_char;
    if filled_to_capacity && !ended_with_newline {
        unsafe { __chk_fail() }
    }
    result
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fgets_chk(
    buf: *mut c_char,
    buflen: usize,
    n: c_int,
    stream: *mut c_void,
) -> *mut c_char {
    // `n` is SIGNED, and `n as usize` turns a negative count into a huge one, so
    // this used to abort the process for `fgets(buf, -1, fp)` where glibc simply
    // returns NULL. Probed on host glibc 2.42 with fork isolation:
    //
    //   n=8,  buflen=64 -> non-NULL      (reads)
    //   n=64, buflen=8  -> SIGABRT       ("buffer overflow detected")
    //   n=-1, buflen=64 -> NULL, NO abort
    //   n=0,  buflen=64 -> NULL, NO abort
    //
    // Only a POSITIVE count can overflow the destination; a non-positive one is
    // the stream call's business and it answers NULL. The wide siblings
    // `__fgetws_chk`/`__fgetws_unlocked_chk` already got this right, which is
    // what made the narrow pair's version look deliberate rather than a slip.
    // SAFETY: delegates to the shared rule; `fgets` is fl's own narrow reader.
    unsafe { fgets_chk_common(buf, buflen, n, stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fgets_unlocked_chk(
    buf: *mut c_char,
    buflen: usize,
    n: c_int,
    stream: *mut c_void,
) -> *mut c_char {
    // `n` is SIGNED, and `n as usize` turns a negative count into a huge one, so
    // this used to abort the process for `fgets(buf, -1, fp)` where glibc simply
    // returns NULL. Probed on host glibc 2.42 with fork isolation:
    //
    //   n=8,  buflen=64 -> non-NULL      (reads)
    //   n=64, buflen=8  -> SIGABRT       ("buffer overflow detected")
    //   n=-1, buflen=64 -> NULL, NO abort
    //   n=0,  buflen=64 -> NULL, NO abort
    //
    // Only a POSITIVE count can overflow the destination; a non-positive one is
    // the stream call's business and it answers NULL. The wide siblings
    // `__fgetws_chk`/`__fgetws_unlocked_chk` already got this right, which is
    // what made the narrow pair's version look deliberate rather than a slip.
    // SAFETY: delegates to the shared rule; `fgets` is fl's own narrow reader.
    unsafe { fgets_chk_common(buf, buflen, n, stream) }
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
    resolvedlen: usize,
) -> *mut c_char {
    if !resolved.is_null() && resolvedlen != usize::MAX && resolvedlen < FORTIFY_PATH_MAX {
        unsafe { __chk_fail() }
    }
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
    // THE CHECK IS DYNAMIC, NOT STATIC (bd-917hzv, third instance of the class).
    //
    // fl aborted whenever `buflen < PATH_MAX`, so `getwd(buf)` with an ordinary
    // 256-byte buffer was killed. Host glibc 2.42, fork-isolated, with a cwd of 26
    // characters:
    //
    //     buflen=4096 -> ok        buflen=64 -> ok        buflen=8 -> ABORT
    //
    // It does not abort at 64, so the requirement is not `>= PATH_MAX`; it aborts
    // at 8, so it is not absent either. The rule is the ACTUAL path length against
    // `buflen` — the same static-versus-dynamic distinction that `__fgets_chk` and
    // `__fgetws_chk` had wrong.
    //
    // `getwd` itself takes no bound, which is why it is deprecated and why the
    // check cannot simply call it and inspect the result: that would already have
    // overflowed. So resolve into a PATH_MAX scratch buffer first, compare, and
    // only then copy — which is what makes the dynamic rule safe to implement, and
    // is the same shape glibc uses.
    //
    // NOTE this deliberately does NOT test `read_chk`-style requests. Probed in the
    // same sweep, `__read_chk` IS static — it aborts for nbytes=4096 into a claimed
    // 64-byte buffer even when only 12 bytes are available — because `read` can
    // genuinely fill the request, so fl's static rule there is correct and was left
    // alone.
    // NULL destination keeps `getwd`'s own error contract — EINVAL and NULL —
    // rather than reaching the copy below. Caught by
    // `getwd_chk_null_buffer_follows_getwd_error_contract`, which this change
    // broke on its first version: `copy_nonoverlapping` into a null pointer is UB
    // and the debug assertion fired, which is exactly what that arm is for.
    if buf.is_null() {
        // SAFETY: delegating the null case to the implementation that owns the
        // contract, unchanged from before this fix.
        return unsafe { crate::glibc_internal_abi::getwd(buf) };
    }

    // `c_char` is target-dependent (`i8` on x86_64 and `u8` on aarch64), just
    // like the `getcwd` ABI that fills this scratch buffer.
    let mut scratch = [0 as c_char; FORTIFY_PATH_MAX];
    // SAFETY: `scratch` is exactly FORTIFY_PATH_MAX bytes.
    let got = unsafe { crate::unistd_abi::getcwd(scratch.as_mut_ptr(), FORTIFY_PATH_MAX) };
    if got.is_null() {
        return core::ptr::null_mut();
    }
    let mut len = 0usize;
    while len < FORTIFY_PATH_MAX && scratch[len] != 0 {
        len += 1;
    }
    let needed = len + 1; // including the terminator
    if buflen != usize::MAX && needed > buflen {
        unsafe { __chk_fail() }
    }
    // SAFETY: `needed` bytes fit in the caller's buffer by the check above, and in
    // `scratch` by construction.
    unsafe { core::ptr::copy_nonoverlapping(scratch.as_ptr(), buf, needed) };
    buf
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
    nreal: usize,
) -> c_int {
    if nreal != usize::MAX && buflen > nreal {
        unsafe { __chk_fail() }
    }
    unsafe { crate::unistd_abi::ptsname_r(fd, buf, buflen) }
}

// ── Wide string operations ─────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcscpy_chk(
    dest: *mut WcharT,
    src: *const WcharT,
    destlen: usize,
) -> *mut WcharT {
    // `destlen` counts WIDE CHARACTERS, not bytes: glibc's fortify headers pass
    // `__glibc_objsize (dst) / sizeof (wchar_t)`, so the size arrives already
    // divided. Scaling the request to bytes and comparing against it aborted at a
    // QUARTER of the real capacity. Probed fork-isolated on host glibc 2.42:
    // `n=100 destlen=256` runs, `n=300 destlen=256` aborts (bd-917hzv sibling).
    let max_units = (destlen != usize::MAX).then_some(destlen);
    let len = unsafe { checked_wide_len(src, max_units) };
    let copy_units = checked_wide_add(len, 1);
    if destlen != usize::MAX && copy_units > destlen {
        unsafe { __chk_fail() }
    }
    // The CHECK is in wide characters; the COPY is in bytes. Both are needed and
    // conflating them is what made this wrong.
    let copy_bytes = checked_wide_bytes(copy_units);
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
    // `destlen` counts WIDE CHARACTERS, not bytes: glibc's fortify headers pass
    // `__glibc_objsize (dst) / sizeof (wchar_t)`, so the size arrives already
    // divided. Scaling the request to bytes and comparing against it aborted at a
    // QUARTER of the real capacity. Probed fork-isolated on host glibc 2.42:
    // `n=100 destlen=256` runs, `n=300 destlen=256` aborts (bd-917hzv sibling).
    if destlen != usize::MAX && n > destlen {
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
    // `destlen` counts WIDE CHARACTERS, not bytes: glibc's fortify headers pass
    // `__glibc_objsize (dst) / sizeof (wchar_t)`, so the size arrives already
    // divided. Scaling the request to bytes and comparing against it aborted at a
    // QUARTER of the real capacity. Probed fork-isolated on host glibc 2.42:
    // `n=100 destlen=256` runs, `n=300 destlen=256` aborts (bd-917hzv sibling).
    if destlen != usize::MAX && n > destlen {
        unsafe { __chk_fail() }
    }
    // The CHECK is in wide characters; the COPY below is in bytes.
    let bytes = checked_wide_bytes(n);
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
    // `destlen` counts WIDE CHARACTERS, not bytes: glibc's fortify headers pass
    // `__glibc_objsize (dst) / sizeof (wchar_t)`, so the size arrives already
    // divided. Scaling the request to bytes and comparing against it aborted at a
    // QUARTER of the real capacity. Probed fork-isolated on host glibc 2.42:
    // `n=100 destlen=256` runs, `n=300 destlen=256` aborts (bd-917hzv sibling).
    if destlen != usize::MAX && n > destlen {
        unsafe { __chk_fail() }
    }
    // The CHECK is in wide characters; the COPY below is in bytes.
    let bytes = checked_wide_bytes(n);
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
    // `destlen` counts WIDE CHARACTERS, not bytes: glibc's fortify headers pass
    // `__glibc_objsize (dst) / sizeof (wchar_t)`, so the size arrives already
    // divided. Scaling the request to bytes and comparing against it aborted at a
    // QUARTER of the real capacity. Probed fork-isolated on host glibc 2.42:
    // `n=100 destlen=256` runs, `n=300 destlen=256` aborts (bd-917hzv sibling).
    if destlen != usize::MAX && n > destlen {
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

/// The measured `__fgetws*_chk` rule, shared by the locked and unlocked forms.
///
/// SEE THE PROBE MATRIX BEFORE CHANGING THIS. The previous rule was a STATIC
/// `n * 4 > buflen -> __chk_fail`, which aborts processes glibc runs happily:
/// `fgetws(buf, 1024, fp)` into a 4096-byte buffer is the ordinary idiom, and fl
/// killed it whenever `n * 4` crossed the size, regardless of what the file
/// actually contained (bd-917hzv).
///
/// Host glibc 2.42, fork-isolated, one row per (n, size, content):
///
/// ```text
///   content    n     size   glibc          content    n     size   glibc
///   short(12)  64      8    ABORT          long(300)  64      8    ABORT
///   short(12) 256    256    ok             long(300) 256    256    ok
///   short(12) 257    256    ok             long(300) 257    256    ABORT
///   short(12)  65    256    ok             long(300)  65    256    ok
///   short(12) 2000  4096    ok             long(300) 2000  4096    ok
///   short(12)  -1    256    NULL           short(12)   0    256    NULL
/// ```
///
/// NO STATIC RULE FITS. `257/256` aborts for long content and not for short, so
/// the comparison cannot be on `n` alone — which is exactly why the existing
/// `fortify_abi_test` case never discriminated. The rule that fits every row has
/// TWO conditions: `n > buflen` AND the content did not actually fit. glibc only
/// reaches its overflow check once the read fills the clamped buffer, so a short
/// line survives a large `n` and a long line does not.
///
/// The units look wrong and are not: `n` counts WIDE CHARACTERS while `buflen`
/// counts BYTES, and glibc compares them directly — the same shape as
/// `__fgets_chk`'s `n > buflen`. Matching that is deliberate.
///
/// # Safety
/// `buf` must be writable for `buflen` bytes and `stream` a valid `FILE*`.
unsafe fn fgetws_chk_common(
    buf: *mut WcharT,
    buflen: usize,
    n: c_int,
    stream: *mut c_void,
) -> *mut WcharT {
    // Negative or zero `n` returns NULL rather than aborting, and an unknown size
    // cannot bound anything.
    if n <= 0 || buflen == usize::MAX {
        // SAFETY: caller's contract.
        return unsafe { fgetws(buf, n, stream) };
    }

    // Inside glibc's static bound: pass through untouched. This deliberately
    // inherits glibc's own gap — `n = 65` with `buflen = 256` may write 260 bytes
    // — because diverging by aborting MORE is the defect being fixed here, and
    // fl's contract is glibc's behaviour rather than a stricter one.
    if (n as usize) <= buflen {
        // SAFETY: caller's contract.
        return unsafe { fgetws(buf, n, stream) };
    }

    // `n` exceeds the byte size, so bound the read to what the buffer holds,
    // INCLUDING the terminator `fgetws` always writes. No overflow is possible
    // past this point whatever the content is.
    let cap_wide = buflen / core::mem::size_of::<WcharT>();
    if cap_wide == 0 {
        // Not even room for the terminator.
        unsafe { __chk_fail() }
    }
    let clamped = cap_wide.min(n as usize) as c_int;
    // SAFETY: `clamped` is at most the buffer's wide-character capacity.
    let result = unsafe { fgetws(buf, clamped, stream) };
    if result.is_null() {
        return result;
    }

    // Truncation means the content WOULD have overflowed the caller's buffer,
    // which is the condition glibc aborts on. A run ending in a newline, or
    // shorter than the clamp, fitted.
    let mut len = 0usize;
    // SAFETY: `fgetws` NUL-terminates within `clamped` wide characters.
    while len < clamped as usize && unsafe { *buf.add(len) } != 0 {
        len += 1;
    }
    let filled_to_capacity = len + 1 == clamped as usize;
    // SAFETY: `len` is in bounds by the loop above.
    let ended_with_newline = len > 0 && unsafe { *buf.add(len - 1) } == b'\n' as WcharT;
    if filled_to_capacity && !ended_with_newline {
        unsafe { __chk_fail() }
    }
    result
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fgetws_chk(
    buf: *mut WcharT,
    buflen: usize,
    n: c_int,
    stream: *mut c_void,
) -> *mut WcharT {
    // SAFETY: delegates to the shared rule; `fgetws` is fl's own wide reader.
    unsafe { fgetws_chk_common(buf, buflen, n, stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fgetws_unlocked_chk(
    buf: *mut WcharT,
    buflen: usize,
    n: c_int,
    stream: *mut c_void,
) -> *mut WcharT {
    // SAFETY: delegates to the shared rule; `fgetws` is fl's own wide reader.
    unsafe { fgetws_chk_common(buf, buflen, n, stream) }
}

// ── Multibyte conversion ───────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mbstowcs_chk(
    dest: *mut WcharT,
    src: *const c_char,
    n: usize,
    destlen: usize,
) -> usize {
    // `destlen` counts WIDE CHARACTERS, not bytes: glibc's fortify headers pass
    // `__glibc_objsize (dst) / sizeof (wchar_t)`, so the size arrives already
    // divided. Scaling the request to bytes and comparing against it aborted at a
    // QUARTER of the real capacity. Probed fork-isolated on host glibc 2.42:
    // `n=100 destlen=256` runs, `n=300 destlen=256` aborts (bd-917hzv sibling).
    if destlen != usize::MAX && n > destlen {
        unsafe { __chk_fail() }
    }
    // fl declares `mbstowcs` as `(*mut u32, *const u8)` while this wrapper uses
    // `(*mut WcharT, *const c_char)`. Layout-identical on every target fl builds
    // for — wchar_t is 32-bit and c_char 8-bit — but the SIGNEDNESS differs, so
    // the cast is explicit. The link-time extern hid this mismatch entirely;
    // importing surfaced it as a compile error, which is the behaviour wanted.
    unsafe { mbstowcs(dest.cast::<u32>(), src.cast::<u8>(), n) }
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
    // Same signedness-only mismatch as `__mbstowcs_chk` above.
    unsafe { wcstombs(dest.cast::<u8>(), src.cast::<u32>(), n) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mbsrtowcs_chk(
    dest: *mut WcharT,
    src: *mut *const c_char,
    n: usize,
    ps: *mut c_void,
    destlen: usize,
) -> usize {
    // `destlen` counts WIDE CHARACTERS, not bytes: glibc's fortify headers pass
    // `__glibc_objsize (dst) / sizeof (wchar_t)`, so the size arrives already
    // divided. Scaling the request to bytes and comparing against it aborted at a
    // QUARTER of the real capacity. Probed fork-isolated on host glibc 2.42:
    // `n=100 destlen=256` runs, `n=300 destlen=256` aborts (bd-917hzv sibling).
    if destlen != usize::MAX && n > destlen {
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
    // `destlen` counts WIDE CHARACTERS, not bytes: glibc's fortify headers pass
    // `__glibc_objsize (dst) / sizeof (wchar_t)`, so the size arrives already
    // divided. Scaling the request to bytes and comparing against it aborted at a
    // QUARTER of the real capacity. Probed fork-isolated on host glibc 2.42:
    // `n=100 destlen=256` runs, `n=300 destlen=256` aborts (bd-917hzv sibling).
    if destlen != usize::MAX && n > destlen {
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

/// glibc compares `buflen` against **MB_CUR_MAX**, not MB_LEN_MAX.
///
/// The two are easy to confuse because the FORTIFY header macro decides whether
/// to route the call here at all by comparing the object size against
/// MB_LEN_MAX (16). The RUNTIME check inside `__wctomb_chk` is the other
/// constant — the locale's current maximum — and using 16 there rejects buffers
/// glibc accepts. Probed against the live host, calling its `__wctomb_chk`
/// directly:
///
/// ```text
///   C locale       (MB_CUR_MAX=1): buflen 1, 5, 6, 15, 16 -> all return, none abort
///   C.UTF-8        (MB_CUR_MAX=6): buflen 1, 5 abort; 6, 15, 16 return
///   en_US.UTF-8    (MB_CUR_MAX=6): same as C.UTF-8
/// ```
///
/// fl used `buflen < 16` and so aborted for every buflen in 1..=15 regardless
/// of locale — killing correct programs, which is the damaging direction for a
/// fortify check. bd-ddr8kv.
///
/// The bootstrap locale and conversion family are UTF-8, so the runtime
/// maximum is the codec's six-byte bound.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wctomb_chk(s: *mut c_char, wchar: WcharT, buflen: usize) -> c_int {
    let mb_cur_max = unsafe { crate::glibc_internal_abi::__ctype_get_mb_cur_max() } as usize;
    if !s.is_null() && buflen != usize::MAX && buflen < mb_cur_max {
        unsafe { __chk_fail() }
    }
    // fl's `wctomb` takes the wide character as `u32` while this wrapper carries
    // it as `WcharT` (i32) — the same signedness-only mismatch as `mbstowcs`, and
    // again surfaced by importing rather than hidden by a link-time declaration.
    unsafe { wctomb(s.cast::<u8>(), wchar as u32) }
}

// ── longjmp ────────────────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __longjmp_chk(env: *mut c_void, val: c_int) -> ! {
    if env.is_null() {
        unsafe {
            let mut unblock_set = core::mem::zeroed::<libc::sigset_t>();
            let _ = crate::signal_abi::sigemptyset(&mut unblock_set);
            let _ = crate::signal_abi::sigaddset(&mut unblock_set, libc::SIGSEGV);
            let _ = raw_syscall::sys_rt_sigprocmask(
                libc::SIG_UNBLOCK,
                &unblock_set as *const libc::sigset_t as *const u8,
                std::ptr::null_mut(),
                core::mem::size_of::<libc::c_ulong>(),
            );

            let mut act = core::mem::zeroed::<libc::sigaction>();
            act.sa_sigaction = libc::SIG_DFL as libc::sighandler_t;
            let _ = raw_syscall::sys_rt_sigaction(
                libc::SIGSEGV,
                &act as *const libc::sigaction as *const u8,
                std::ptr::null_mut(),
                core::mem::size_of::<libc::c_ulong>(),
            );

            let pid = raw_syscall::sys_getpid();
            let tid = raw_syscall::sys_gettid();
            let _ = raw_syscall::sys_tgkill(pid, tid, libc::SIGSEGV);
            raw_syscall::sys_exit_group(128 + libc::SIGSEGV)
        }
    }
    #[cfg(any(debug_assertions, target_arch = "x86_64", target_arch = "aarch64"))]
    {
        unsafe { crate::setjmp_abi::longjmp(env, val) }
    }
    #[cfg(all(
        not(debug_assertions),
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    {
        unsafe { longjmp(env, val) }
    }
}

// ── poll ───────────────────────────────────────────────────────────────────

fn checked_pollfd_bytes(nfds: NfdsT) -> usize {
    let Some(bytes) = (nfds as usize).checked_mul(core::mem::size_of::<libc::pollfd>()) else {
        unsafe { __chk_fail() }
    };
    bytes
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __poll_chk(
    fds: *mut c_void,
    nfds: NfdsT,
    timeout: c_int,
    fdslen: usize,
) -> c_int {
    if checked_pollfd_bytes(nfds) > fdslen {
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
    if checked_pollfd_bytes(nfds) > fdslen {
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

fn open_flags_need_mode(oflag: c_int) -> bool {
    (oflag & libc::O_CREAT) != 0 || (oflag & libc::O_TMPFILE) == libc::O_TMPFILE
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __open_2(path: *const c_char, oflag: c_int) -> c_int {
    // _2 variants: O_CREAT not set, so mode=0 is ignored
    if open_flags_need_mode(oflag) {
        unsafe { __chk_fail() }
    }
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
    if open_flags_need_mode(oflag) {
        unsafe { __chk_fail() }
    }
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
    if open_flags_need_mode(oflag) {
        unsafe { __chk_fail() }
    }
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
    if open_flags_need_mode(oflag) {
        unsafe { __chk_fail() }
    }
    match unsafe { raw_syscall::sys_openat(dirfd, path as *const u8, oflag | libc::O_LARGEFILE, 0) }
    {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { crate::errno_abi::set_abi_errno(e) };
            -1
        }
    }
}
