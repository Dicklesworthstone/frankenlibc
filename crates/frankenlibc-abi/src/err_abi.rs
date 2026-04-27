//! ABI layer for `<err.h>` — BSD/GNU error reporting functions.
//!
//! These functions format error messages to stderr with the program name prefix.
//! - `warn`/`vwarn`: print "progname: message: strerror(errno)\n"
//! - `warnx`/`vwarnx`: print "progname: message\n"
//! - `err`/`verr`: like warn + exit(eval)
//! - `errx`/`verrx`: like warnx + exit(eval)

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_core::stdio::{ValueArgKind, count_printf_args, positional_printf_arg_plan};

use crate::malloc_abi::known_remaining;
use crate::util::scan_c_string;

const MAX_PUBLISHED_PROGNAME_BYTES: usize = 4096;

/// Read a caller-supplied err(3) format string without walking past tracked
/// allocations that never reached a NUL terminator.
#[inline]
unsafe fn read_format_bytes(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    Some(bytes.to_vec())
}

// ---------------------------------------------------------------------------
// Program name helper
// ---------------------------------------------------------------------------

/// Returns the short program name used by GNU/BSD err.h diagnostics.
///
/// Glibc bases this on `program_invocation_short_name`, which is the basename
/// of `argv[0]`. In unit tests and interpose-style loading our CRT startup path
/// may not have initialized that global, so `/proc/self/cmdline` is the best
/// process-lifetime fallback. `/proc/self/comm` is only a last resort because
/// Linux truncates it to `TASK_COMM_LEN`.
fn get_progname() -> Vec<u8> {
    use std::sync::OnceLock;
    static FALLBACK_PROGNAME: OnceLock<Vec<u8>> = OnceLock::new();

    let published = crate::startup_abi::program_invocation_short_name
        .load(std::sync::atomic::Ordering::Acquire);
    if !published.is_null() {
        // Startup publishes `argv[0]` storage for process lifetime, but still
        // cap the scan so a bad embedder cannot make diagnostics walk memory.
        let (len, terminated) =
            unsafe { scan_c_string(published, Some(MAX_PUBLISHED_PROGNAME_BYTES)) };
        if terminated && len > 0 {
            let bytes = unsafe { core::slice::from_raw_parts(published.cast::<u8>(), len) };
            return bytes.to_vec();
        }
    }

    FALLBACK_PROGNAME
        .get_or_init(|| {
            proc_cmdline_progname()
                .or_else(proc_comm_progname)
                .unwrap_or_else(|| b"?".to_vec())
        })
        .clone()
}

// `basename_bytes` is now provided by frankenlibc-core::err::basename_bytes
// (bd-err-1, epic bd-err-epic).
use frankenlibc_core::err::basename_bytes;

fn proc_cmdline_progname() -> Option<Vec<u8>> {
    let cmdline = std::fs::read("/proc/self/cmdline").ok()?;
    let argv0 = cmdline.split(|&b| b == 0).next()?;
    let basename = basename_bytes(argv0);
    (!basename.is_empty()).then(|| basename.to_vec())
}

fn proc_comm_progname() -> Option<Vec<u8>> {
    let name = std::fs::read("/proc/self/comm").ok()?;
    let trimmed: Vec<u8> = name
        .into_iter()
        .take_while(|&b| b != b'\n' && b != 0)
        .collect();
    (!trimmed.is_empty()).then_some(trimmed)
}

// ---------------------------------------------------------------------------
// Core formatting and output
// ---------------------------------------------------------------------------

/// Format and write an err.h-style message to stderr.
///
/// Delegates the byte-level formatting to
/// [`frankenlibc_core::err::format_err_message`] (bd-err-2). This abi
/// layer remains responsible for: rendering the printf template +
/// args, looking up the errno string, and atomically writing the
/// result to fd 2.
fn write_err_message(fmt_bytes: &[u8], arg_buf: &[u64], arg_count: usize, with_errno: bool) {
    let saved_errno = unsafe { *crate::errno_abi::__errno_location() };
    let progname = get_progname();

    // Render the printf template into bytes.
    let message: Vec<u8> = if fmt_bytes.is_empty() {
        Vec::new()
    } else {
        unsafe { super::stdio_abi::render_printf(fmt_bytes, arg_buf.as_ptr(), arg_count) }
    };

    // Resolve errno → byte string (lifetime is &'static so we can pass
    // a reference through to the formatter).
    let errno_msg_opt: Option<&[u8]> = if with_errno {
        Some(strerror_bytes(saved_errno))
    } else {
        None
    };

    let out = frankenlibc_core::err::format_err_message(&progname, &message, errno_msg_opt);

    unsafe {
        crate::unistd_abi::write(2, out.as_ptr() as *const c_void, out.len());
        crate::errno_abi::set_abi_errno(saved_errno);
    }
}

/// Variant of `write_err_message` for the BSD `*c` family (`warnc`,
/// `errc`, etc.) that appends the strerror of an explicitly-supplied
/// error code instead of consulting the global errno.
fn write_err_message_with_code(fmt_bytes: &[u8], arg_buf: &[u64], arg_count: usize, code: c_int) {
    let saved_errno = unsafe { *crate::errno_abi::__errno_location() };
    let progname = get_progname();

    let message: Vec<u8> = if fmt_bytes.is_empty() {
        Vec::new()
    } else {
        unsafe { super::stdio_abi::render_printf(fmt_bytes, arg_buf.as_ptr(), arg_count) }
    };

    let errno_msg = strerror_bytes(code);

    let out = frankenlibc_core::err::format_err_message(&progname, &message, Some(errno_msg));

    unsafe {
        crate::unistd_abi::write(2, out.as_ptr() as *const c_void, out.len());
        crate::errno_abi::set_abi_errno(saved_errno);
    }
}

/// va_list variant: parse + extract args from `ap`, then write with
/// the explicit code.
fn vformat_and_write_with_code(fmt: *const c_char, ap: *mut c_void, code: c_int) {
    let Some(fmt_bytes) = (unsafe { read_format_bytes(fmt) }) else {
        write_err_message_with_code(&[], &[], 0, code);
        return;
    };
    use frankenlibc_core::stdio::printf::parse_format_string;
    let segments = parse_format_string(&fmt_bytes);
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    unsafe {
        super::stdio_abi::vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count);
    }
    write_err_message_with_code(&fmt_bytes, &arg_buf, extract_count, code);
}

/// Convert errno to a human-readable byte string.
fn strerror_bytes(errnum: c_int) -> &'static [u8] {
    frankenlibc_core::errno::strerror_message(errnum).as_bytes()
}

// ---------------------------------------------------------------------------
// Variadic argument extraction (same pattern as syslog)
// ---------------------------------------------------------------------------

macro_rules! extract_err_args {
    ($segments:expr, $args:expr, $buf:expr, $extract_count:expr) => {{
        use frankenlibc_core::stdio::printf::FormatSegment;
        let mut _idx = 0usize;
        if let Some(_plan) = positional_printf_arg_plan($segments) {
            for _kind in _plan.iter().take($extract_count) {
                match _kind {
                    ValueArgKind::Gp => {
                        if _idx < $extract_count {
                            $buf[_idx] = unsafe { $args.arg::<u64>() };
                            _idx += 1;
                        }
                    }
                    ValueArgKind::Fp => {
                        if _idx < $extract_count {
                            $buf[_idx] = unsafe { $args.arg::<f64>() }.to_bits();
                            _idx += 1;
                        }
                    }
                }
            }
        } else {
            for seg in $segments {
                if let FormatSegment::Spec(spec) = seg {
                    if spec.width.uses_arg() && _idx < $extract_count {
                        $buf[_idx] = unsafe { $args.arg::<u64>() };
                        _idx += 1;
                    }
                    if spec.precision.uses_arg() && _idx < $extract_count {
                        $buf[_idx] = unsafe { $args.arg::<u64>() };
                        _idx += 1;
                    }
                    match spec.conversion {
                        b'%' => {}
                        b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                            if _idx < $extract_count {
                                $buf[_idx] = unsafe { $args.arg::<f64>() }.to_bits();
                                _idx += 1;
                            }
                        }
                        _ => {
                            if _idx < $extract_count {
                                $buf[_idx] = unsafe { $args.arg::<u64>() };
                                _idx += 1;
                            }
                        }
                    }
                }
            }
        }
        _idx
    }};
}

/// Parse format string and extract args from a va_list pointer into a buffer,
/// then call `write_err_message`.
fn vformat_and_write(fmt: *const c_char, ap: *mut c_void, with_errno: bool) {
    let Some(fmt_bytes) = (unsafe { read_format_bytes(fmt) }) else {
        write_err_message(&[], &[], 0, with_errno);
        return;
    };
    use frankenlibc_core::stdio::printf::parse_format_string;
    let segments = parse_format_string(&fmt_bytes);
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    unsafe {
        super::stdio_abi::vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count);
    }
    write_err_message(&fmt_bytes, &arg_buf, extract_count, with_errno);
}

// ---------------------------------------------------------------------------
// warn / vwarn
// ---------------------------------------------------------------------------

/// BSD `warn` — print "progname: message: strerror(errno)\n" to stderr.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn warn(fmt: *const c_char, mut args: ...) {
    if fmt.is_null() {
        write_err_message(&[], &[], 0, true);
        return;
    }
    let Some(fmt_bytes) = (unsafe { read_format_bytes(fmt) }) else {
        write_err_message(&[], &[], 0, true);
        return;
    };
    use frankenlibc_core::stdio::printf::parse_format_string;
    let segments = parse_format_string(&fmt_bytes);
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_err_args!(&segments, &mut args, &mut arg_buf, extract_count);
    write_err_message(&fmt_bytes, &arg_buf, extract_count, true);
}

/// BSD `vwarn` — va_list version of `warn`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vwarn(fmt: *const c_char, ap: *mut c_void) {
    if fmt.is_null() {
        write_err_message(&[], &[], 0, true);
        return;
    }
    vformat_and_write(fmt, ap, true);
}

// ---------------------------------------------------------------------------
// warnx / vwarnx
// ---------------------------------------------------------------------------

/// BSD `warnx` — print "progname: message\n" to stderr (no errno).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn warnx(fmt: *const c_char, mut args: ...) {
    if fmt.is_null() {
        write_err_message(&[], &[], 0, false);
        return;
    }
    let Some(fmt_bytes) = (unsafe { read_format_bytes(fmt) }) else {
        write_err_message(&[], &[], 0, false);
        return;
    };
    use frankenlibc_core::stdio::printf::parse_format_string;
    let segments = parse_format_string(&fmt_bytes);
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_err_args!(&segments, &mut args, &mut arg_buf, extract_count);
    write_err_message(&fmt_bytes, &arg_buf, extract_count, false);
}

/// BSD `vwarnx` — va_list version of `warnx`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vwarnx(fmt: *const c_char, ap: *mut c_void) {
    if fmt.is_null() {
        write_err_message(&[], &[], 0, false);
        return;
    }
    vformat_and_write(fmt, ap, false);
}

// ---------------------------------------------------------------------------
// err / verr
// ---------------------------------------------------------------------------

/// BSD `err` — print "progname: message: strerror(errno)\n" to stderr, then exit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn err(eval: c_int, fmt: *const c_char, mut args: ...) -> ! {
    if fmt.is_null() {
        write_err_message(&[], &[], 0, true);
    } else {
        if let Some(fmt_bytes) = unsafe { read_format_bytes(fmt) } {
            use frankenlibc_core::stdio::printf::parse_format_string;
            let segments = parse_format_string(&fmt_bytes);
            let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
            let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
            extract_err_args!(&segments, &mut args, &mut arg_buf, extract_count);
            write_err_message(&fmt_bytes, &arg_buf, extract_count, true);
        } else {
            write_err_message(&[], &[], 0, true);
        }
    }
    invoke_exit_hook(eval);
    frankenlibc_core::syscall::sys_exit_group(eval)
}

/// BSD `verr` — va_list version of `err`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn verr(eval: c_int, fmt: *const c_char, ap: *mut c_void) -> ! {
    if fmt.is_null() {
        write_err_message(&[], &[], 0, true);
    } else {
        vformat_and_write(fmt, ap, true);
    }
    invoke_exit_hook(eval);
    frankenlibc_core::syscall::sys_exit_group(eval)
}

// ---------------------------------------------------------------------------
// errx / verrx
// ---------------------------------------------------------------------------

/// BSD `errx` — print "progname: message\n" to stderr, then exit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn errx(eval: c_int, fmt: *const c_char, mut args: ...) -> ! {
    if fmt.is_null() {
        write_err_message(&[], &[], 0, false);
    } else {
        if let Some(fmt_bytes) = unsafe { read_format_bytes(fmt) } {
            use frankenlibc_core::stdio::printf::parse_format_string;
            let segments = parse_format_string(&fmt_bytes);
            let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
            let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
            extract_err_args!(&segments, &mut args, &mut arg_buf, extract_count);
            write_err_message(&fmt_bytes, &arg_buf, extract_count, false);
        } else {
            write_err_message(&[], &[], 0, false);
        }
    }
    invoke_exit_hook(eval);
    frankenlibc_core::syscall::sys_exit_group(eval)
}

/// BSD `verrx` — va_list version of `errx`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn verrx(eval: c_int, fmt: *const c_char, ap: *mut c_void) -> ! {
    if fmt.is_null() {
        write_err_message(&[], &[], 0, false);
    } else {
        vformat_and_write(fmt, ap, false);
    }
    invoke_exit_hook(eval);
    frankenlibc_core::syscall::sys_exit_group(eval)
}

// ---------------------------------------------------------------------------
// warnc / vwarnc — BSD/NetBSD explicit-code variants
// ---------------------------------------------------------------------------

/// BSD `warnc` — like `warn`, but uses the explicitly-supplied error
/// `code` for the strerror suffix instead of consulting the global
/// errno. Useful when the caller has already preserved errno or wants
/// to report a different code than the one currently set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn warnc(code: c_int, fmt: *const c_char, mut args: ...) {
    if fmt.is_null() {
        write_err_message_with_code(&[], &[], 0, code);
        return;
    }
    let Some(fmt_bytes) = (unsafe { read_format_bytes(fmt) }) else {
        write_err_message_with_code(&[], &[], 0, code);
        return;
    };
    use frankenlibc_core::stdio::printf::parse_format_string;
    let segments = parse_format_string(&fmt_bytes);
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_err_args!(&segments, &mut args, &mut arg_buf, extract_count);
    write_err_message_with_code(&fmt_bytes, &arg_buf, extract_count, code);
}

/// BSD `vwarnc` — va_list version of `warnc`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vwarnc(code: c_int, fmt: *const c_char, ap: *mut c_void) {
    if fmt.is_null() {
        write_err_message_with_code(&[], &[], 0, code);
        return;
    }
    vformat_and_write_with_code(fmt, ap, code);
}

// ---------------------------------------------------------------------------
// errc / verrc — BSD/NetBSD explicit-code exit variants
// ---------------------------------------------------------------------------

/// BSD `errc` — like `err`, but uses the explicitly-supplied error
/// `code` for the strerror suffix instead of consulting the global
/// errno. Always exits with status `eval` after printing.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn errc(eval: c_int, code: c_int, fmt: *const c_char, mut args: ...) -> ! {
    if fmt.is_null() {
        write_err_message_with_code(&[], &[], 0, code);
    } else {
        if let Some(fmt_bytes) = unsafe { read_format_bytes(fmt) } {
            use frankenlibc_core::stdio::printf::parse_format_string;
            let segments = parse_format_string(&fmt_bytes);
            let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
            let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
            extract_err_args!(&segments, &mut args, &mut arg_buf, extract_count);
            write_err_message_with_code(&fmt_bytes, &arg_buf, extract_count, code);
        } else {
            write_err_message_with_code(&[], &[], 0, code);
        }
    }
    invoke_exit_hook(eval);
    frankenlibc_core::syscall::sys_exit_group(eval)
}

/// BSD `verrc` — va_list version of `errc`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn verrc(eval: c_int, code: c_int, fmt: *const c_char, ap: *mut c_void) -> ! {
    if fmt.is_null() {
        write_err_message_with_code(&[], &[], 0, code);
    } else {
        vformat_and_write_with_code(fmt, ap, code);
    }
    invoke_exit_hook(eval);
    frankenlibc_core::syscall::sys_exit_group(eval)
}

// ---------------------------------------------------------------------------
// err_set_exit (BSD libutil pre-exit hook)
// ---------------------------------------------------------------------------

/// FFI type of the err(3) pre-exit hook.
pub type ErrExitHook = unsafe extern "C" fn(c_int);

static ERR_EXIT_HOOK: std::sync::Mutex<Option<ErrExitHook>> = std::sync::Mutex::new(None);

/// Internal: invoke the registered err-exit hook (if any) with the
/// exit code that err()/errx()/errc() is about to use. Called by
/// each fatal exit path immediately before `sys_exit_group`. The
/// hook may legally `_exit()` itself (skipping the rest of the
/// fatal path) — we don't impose any constraint on its return
/// behavior.
fn invoke_exit_hook(eval: c_int) {
    let hook = { *ERR_EXIT_HOOK.lock().unwrap_or_else(|e| e.into_inner()) };
    if let Some(f) = hook {
        unsafe { f(eval) };
    }
}

/// BSD `err_set_exit(func)` — register a global hook that
/// err()/errx()/errc()/verr()/verrx()/verrc() invoke immediately
/// before they call `exit()`. The hook receives the exit code
/// that the fatal path is about to use.
///
/// Pass `NULL` (i.e. `None` from Rust) to clear the hook and
/// restore default behavior. Returns the previously-installed
/// hook (or `None` if no custom hook was installed).
///
/// Used by daemons and utilities to release locks, flush logs, or
/// remove pidfiles when a fatal error path is taken.
///
/// # Safety
///
/// `func`, when non-NULL, must be a callable `extern "C"` function
/// pointer. The hook will be invoked from inside fatal-error
/// paths; it must be async-signal-safe to whatever extent the
/// caller's runtime requires (the err family already constrains
/// itself to write(2) for output, so the hook inherits the same
/// constraints).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn err_set_exit(func: Option<ErrExitHook>) -> Option<ErrExitHook> {
    let mut cell = ERR_EXIT_HOOK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = *cell;
    *cell = func;
    prev
}
