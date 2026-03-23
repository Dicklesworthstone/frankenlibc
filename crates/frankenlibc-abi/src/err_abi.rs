//! ABI layer for `<err.h>` — BSD/GNU error reporting functions.
//!
//! These functions format error messages to stderr with the program name prefix.
//! - `warn`/`vwarn`: print "progname: message: strerror(errno)\n"
//! - `warnx`/`vwarnx`: print "progname: message\n"
//! - `err`/`verr`: like warn + exit(eval)
//! - `errx`/`verrx`: like warnx + exit(eval)

use std::ffi::{c_char, c_int, c_void};

// ---------------------------------------------------------------------------
// Program name helper
// ---------------------------------------------------------------------------

/// Returns the short program name by reading `/proc/self/comm`.
/// Falls back to `"?"` if unavailable.
fn get_progname() -> &'static [u8] {
    use std::sync::OnceLock;
    static PROGNAME: OnceLock<Vec<u8>> = OnceLock::new();
    PROGNAME.get_or_init(|| {
        if let Ok(name) = std::fs::read("/proc/self/comm") {
            let trimmed: Vec<u8> = name
                .into_iter()
                .take_while(|&b| b != b'\n' && b != 0)
                .collect();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        b"?".to_vec()
    })
}

// ---------------------------------------------------------------------------
// Core formatting and output
// ---------------------------------------------------------------------------

/// Format and write an err.h-style message to stderr.
///
/// If `fmt_bytes` is non-empty, the message is printf-formatted from the
/// provided arg buffer. If `with_errno` is true, appends ": strerror(errno)".
fn write_err_message(fmt_bytes: &[u8], arg_buf: &[u64], arg_count: usize, with_errno: bool) {
    let progname = get_progname();

    // Build the output: "progname: "
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(progname);
    out.extend_from_slice(b": ");

    // Append formatted message if format string is non-empty.
    if !fmt_bytes.is_empty() {
        let rendered =
            unsafe { super::stdio_abi::render_printf(fmt_bytes, arg_buf.as_ptr(), arg_count) };
        out.extend_from_slice(&rendered);
    }

    // Append errno string if requested.
    if with_errno {
        if !fmt_bytes.is_empty() {
            out.extend_from_slice(b": ");
        }
        let errno_val = unsafe { *crate::errno_abi::__errno_location() };
        let errno_msg = strerror_bytes(errno_val);
        out.extend_from_slice(errno_msg);
    }

    out.push(b'\n');

    // Write to stderr (fd 2) atomically.
    unsafe {
        crate::unistd_abi::write(2, out.as_ptr() as *const c_void, out.len());
    }
}

/// Convert errno to a human-readable byte string.
fn strerror_bytes(errnum: c_int) -> &'static [u8] {
    let ptr = unsafe { crate::string_abi::strerror(errnum) };
    if ptr.is_null() {
        return b"Unknown error";
    }
    // SAFETY: strerror returns a valid C string from static storage.
    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
    cstr.to_bytes()
}

// ---------------------------------------------------------------------------
// Variadic argument extraction (same pattern as syslog)
// ---------------------------------------------------------------------------

macro_rules! extract_err_args {
    ($segments:expr, $args:expr, $buf:expr, $extract_count:expr) => {{
        use frankenlibc_core::stdio::printf::{FormatSegment, Precision, Width};
        let mut _idx = 0usize;
        for seg in $segments {
            if let FormatSegment::Spec(spec) = seg {
                if matches!(spec.width, Width::FromArg) && _idx < $extract_count {
                    $buf[_idx] = unsafe { $args.arg::<u64>() };
                    _idx += 1;
                }
                if matches!(spec.precision, Precision::FromArg) && _idx < $extract_count {
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
        _idx
    }};
}

/// Parse format string and extract args from a va_list pointer into a buffer,
/// then call `write_err_message`.
fn vformat_and_write(fmt: *const c_char, ap: *mut c_void, with_errno: bool) {
    let fmt_bytes = unsafe { super::stdio_abi::c_str_bytes(fmt) };
    use frankenlibc_core::stdio::printf::parse_format_string;
    let segments = parse_format_string(fmt_bytes);
    let extract_count = super::stdio_abi::count_printf_args(&segments);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    unsafe {
        super::stdio_abi::vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count);
    }
    write_err_message(fmt_bytes, &arg_buf, extract_count, with_errno);
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
    let fmt_bytes = unsafe { super::stdio_abi::c_str_bytes(fmt) };
    use frankenlibc_core::stdio::printf::parse_format_string;
    let segments = parse_format_string(fmt_bytes);
    let extract_count = super::stdio_abi::count_printf_args(&segments);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_err_args!(&segments, &mut args, &mut arg_buf, extract_count);
    write_err_message(fmt_bytes, &arg_buf, extract_count, true);
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
    let fmt_bytes = unsafe { super::stdio_abi::c_str_bytes(fmt) };
    use frankenlibc_core::stdio::printf::parse_format_string;
    let segments = parse_format_string(fmt_bytes);
    let extract_count = super::stdio_abi::count_printf_args(&segments);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_err_args!(&segments, &mut args, &mut arg_buf, extract_count);
    write_err_message(fmt_bytes, &arg_buf, extract_count, false);
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
        let fmt_bytes = unsafe { super::stdio_abi::c_str_bytes(fmt) };
        use frankenlibc_core::stdio::printf::parse_format_string;
        let segments = parse_format_string(fmt_bytes);
        let extract_count = super::stdio_abi::count_printf_args(&segments);
        let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
        extract_err_args!(&segments, &mut args, &mut arg_buf, extract_count);
        write_err_message(fmt_bytes, &arg_buf, extract_count, true);
    }
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
        let fmt_bytes = unsafe { super::stdio_abi::c_str_bytes(fmt) };
        use frankenlibc_core::stdio::printf::parse_format_string;
        let segments = parse_format_string(fmt_bytes);
        let extract_count = super::stdio_abi::count_printf_args(&segments);
        let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
        extract_err_args!(&segments, &mut args, &mut arg_buf, extract_count);
        write_err_message(fmt_bytes, &arg_buf, extract_count, false);
    }
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
    frankenlibc_core::syscall::sys_exit_group(eval)
}
