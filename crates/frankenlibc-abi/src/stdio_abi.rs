//! ABI layer for `<stdio.h>` functions.
//!
//! Provides the full POSIX stdio surface: file stream management (fopen/fclose),
//! buffered I/O (fread/fwrite/fgetc/fputc/fgets/fputs), seeking (fseek/ftell/rewind),
//! status (feof/ferror/clearerr), buffering control (setvbuf/setbuf), and
//! character output (putchar/puts/getchar). The printf family is handled via
//! the core printf formatting engine with manual va_list extraction.
//!
//! Architecture: A global stream registry maps opaque `FILE*` addresses to
//! `StdioStream` instances from frankenlibc-core. stdin/stdout/stderr are
//! pre-registered at well-known sentinel addresses.

use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::os::raw::c_long;
use std::sync::{Mutex, OnceLock};

use frankenlibc_core::errno;
use frankenlibc_core::stdio::{BufMode, OpenFlags, StdioStream, flags_to_oflags, parse_mode};
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::malloc_abi::{known_remaining, malloc};
use crate::runtime_policy;
use crate::unistd_abi::{sys_read_fd, sys_write_fd};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn repair_enabled(heals_enabled: bool, action: MembraneAction) -> bool {
    heals_enabled || matches!(action, MembraneAction::Repair(_))
}

unsafe fn scan_c_str_len(ptr: *const c_char, bound: Option<usize>) -> (usize, bool) {
    match bound {
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
            // SAFETY: caller guarantees `ptr` references a NUL-terminated C string
            // when unbounded scan mode is requested.
            while unsafe { *ptr.add(len) } != 0 {
                len = len.saturating_add(1);
            }
            (len, true)
        }
    }
}

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

// ---------------------------------------------------------------------------
// Stream registry
// ---------------------------------------------------------------------------

/// Sentinel FILE* addresses for the three standard streams.
/// These are distinct non-null addresses that cannot collide with heap pointers.
const STDIN_SENTINEL: usize = 0x1000_0001;
const STDOUT_SENTINEL: usize = 0x1000_0002;
const STDERR_SENTINEL: usize = 0x1000_0003;

/// Next stream ID for dynamically opened files.
static NEXT_STREAM_ID: Mutex<usize> = Mutex::new(0x1000_0010);

struct StreamRegistry {
    streams: HashMap<usize, StdioStream>,
}

impl StreamRegistry {
    fn new() -> Self {
        let mut streams = HashMap::new();

        // Pre-register stdin (fd 0).
        let stdin_flags = OpenFlags {
            readable: true,
            ..Default::default()
        };
        streams.insert(
            STDIN_SENTINEL,
            StdioStream::new(libc::STDIN_FILENO, stdin_flags),
        );

        // Pre-register stdout (fd 1).
        let stdout_flags = OpenFlags {
            writable: true,
            ..Default::default()
        };
        streams.insert(
            STDOUT_SENTINEL,
            StdioStream::new(libc::STDOUT_FILENO, stdout_flags),
        );

        // Pre-register stderr (fd 2).
        let stderr_flags = OpenFlags {
            writable: true,
            ..Default::default()
        };
        streams.insert(
            STDERR_SENTINEL,
            StdioStream::new(libc::STDERR_FILENO, stderr_flags),
        );

        Self { streams }
    }
}

fn registry() -> &'static Mutex<StreamRegistry> {
    static REG: OnceLock<Mutex<StreamRegistry>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(StreamRegistry::new()))
}

fn alloc_stream_id() -> usize {
    let mut next = NEXT_STREAM_ID.lock().unwrap_or_else(|e| e.into_inner());
    let id = *next;
    *next = id.wrapping_add(1);
    id
}

/// Flush a stream's pending write data to its fd. Returns true on success.
unsafe fn flush_stream(stream: &mut StdioStream) -> bool {
    let pending = stream.pending_flush();
    if pending.is_empty() {
        return true;
    }
    let fd = stream.fd();
    let data = pending.to_vec();
    let rc = unsafe { sys_write_fd(fd, data.as_ptr().cast(), data.len()) };
    if rc >= 0 && rc as usize == data.len() {
        stream.mark_flushed();
        true
    } else {
        stream.set_error();
        false
    }
}

/// Fill a stream's read buffer from its fd. Returns bytes read (0 on EOF, -1 on error).
unsafe fn refill_stream(stream: &mut StdioStream) -> isize {
    let mut tmp = [0u8; 8192];
    let fd = stream.fd();
    let rc = unsafe { sys_read_fd(fd, tmp.as_mut_ptr().cast(), tmp.len()) };
    if rc > 0 {
        stream.fill_read_buffer(&tmp[..rc as usize]);
        rc
    } else if rc == 0 {
        stream.set_eof();
        0
    } else {
        stream.set_error();
        -1
    }
}

// ---------------------------------------------------------------------------
// stdin / stdout / stderr accessors
// ---------------------------------------------------------------------------

/// Global `stdin` pointer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static stdin: usize = STDIN_SENTINEL;

/// Global `stdout` pointer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static stdout: usize = STDOUT_SENTINEL;

/// Global `stderr` pointer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static stderr: usize = STDERR_SENTINEL;

// ---------------------------------------------------------------------------
// fopen / fclose
// ---------------------------------------------------------------------------

/// POSIX `fopen`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fopen(pathname: *const c_char, mode: *const c_char) -> *mut c_void {
    if pathname.is_null() || mode.is_null() {
        return std::ptr::null_mut();
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Stdio, pathname as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return std::ptr::null_mut();
    }

    // Parse mode string.
    let mode_bytes = unsafe { CStr::from_ptr(mode) }.to_bytes();
    let Some(open_flags) = parse_mode(mode_bytes) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return std::ptr::null_mut();
    };

    // Convert to O_* flags and call open(2) via libc syscall.
    let oflags = flags_to_oflags(&open_flags);
    let create_mode: libc::mode_t = 0o666;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat as c_long,
            libc::AT_FDCWD,
            pathname,
            oflags,
            create_mode,
        ) as c_int
    };

    if fd < 0 {
        unsafe { set_abi_errno(errno::ENOENT) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 30, true);
        return std::ptr::null_mut();
    }

    // Create stream and register it.
    let mut stream = StdioStream::new(fd, open_flags);
    if open_flags.append {
        // POSIX append streams start at end-of-file for logical position tracking.
        let end_off = unsafe { libc::syscall(libc::SYS_lseek as c_long, fd, 0, libc::SEEK_END) };
        if end_off >= 0 {
            stream.set_offset(end_off as i64);
        }
    }
    let id = alloc_stream_id();
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.insert(id, stream);

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 30, false);
    id as *mut c_void
}

/// POSIX `fclose`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fclose(stream: *mut c_void) -> c_int {
    let id = stream as usize;
    if id == 0 {
        return libc::EOF;
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return libc::EOF;
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut s) = reg.streams.remove(&id) else {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return libc::EOF;
    };

    let fd = s.fd();
    // Flush pending writes.
    let pending = s.prepare_close();
    let mut adverse = false;

    if !pending.is_empty() && fd >= 0 {
        let rc = unsafe { sys_write_fd(fd, pending.as_ptr().cast(), pending.len()) };
        if rc < 0 || rc as usize != pending.len() {
            adverse = true;
        }
    }

    // Close the fd (don't close stdin/stdout/stderr sentinel fds).
    if fd >= 0 && id != STDIN_SENTINEL && id != STDOUT_SENTINEL && id != STDERR_SENTINEL {
        let rc = unsafe { libc::syscall(libc::SYS_close as c_long, fd) };
        if rc < 0 {
            adverse = true;
        }
    }

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, adverse);
    if adverse { libc::EOF } else { 0 }
}

// ---------------------------------------------------------------------------
// fflush
// ---------------------------------------------------------------------------

/// POSIX `fflush`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fflush(stream: *mut c_void) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Stdio, stream as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 4, true);
        return libc::EOF;
    }

    // NULL stream: flush all open streams.
    if stream.is_null() {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let mut any_fail = false;
        let ids: Vec<usize> = reg.streams.keys().copied().collect();
        for id in ids {
            if let Some(s) = reg.streams.get_mut(&id)
                && !unsafe { flush_stream(s) }
            {
                any_fail = true;
            }
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 20, any_fail);
        return if any_fail { libc::EOF } else { 0 };
    }

    let id = stream as usize;
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        let ok = unsafe { flush_stream(s) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 8, !ok);
        if ok { 0 } else { libc::EOF }
    } else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 4, true);
        libc::EOF
    }
}

// ---------------------------------------------------------------------------
// fgetc / fputc
// ---------------------------------------------------------------------------

/// POSIX `fgetc`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetc(stream: *mut c_void) -> c_int {
    let id = stream as usize;
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 1, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    };

    // Try buffered read first.
    let data = s.buffered_read(1);
    if !data.is_empty() {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
        return data[0] as c_int;
    }

    // Refill from fd.
    if s.is_eof() || s.is_error() {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    }
    let rc = unsafe { refill_stream(s) };
    if rc <= 0 {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return libc::EOF;
    }

    let data = s.buffered_read(1);
    let result = if data.is_empty() {
        libc::EOF
    } else {
        data[0] as c_int
    };
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, result == libc::EOF);
    result
}

/// POSIX `fputc`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fputc(c: c_int, stream: *mut c_void) -> c_int {
    let id = stream as usize;
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 1, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    }

    let byte = c as u8;
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    };

    let flush_data = s.buffer_write(&[byte]);
    if !flush_data.is_empty() {
        let fd = s.fd();
        let rc = unsafe { sys_write_fd(fd, flush_data.as_ptr().cast(), flush_data.len()) };
        if rc >= 0 && rc as usize == flush_data.len() {
            s.mark_flushed();
        } else {
            s.set_error();
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 8, true);
            return libc::EOF;
        }
    }

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
    byte as c_int
}

// ---------------------------------------------------------------------------
// fgets / fputs
// ---------------------------------------------------------------------------

/// POSIX `fgets`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgets(buf: *mut c_char, size: c_int, stream: *mut c_void) -> *mut c_char {
    if buf.is_null() || size <= 0 {
        return std::ptr::null_mut();
    }
    let id = stream as usize;
    let max = (size - 1) as usize; // Leave room for NUL.

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, max, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return std::ptr::null_mut();
    };

    let mut written = 0usize;
    while written < max {
        // Try one byte from buffer.
        let data = s.buffered_read(1);
        let byte = if !data.is_empty() {
            data[0]
        } else {
            if s.is_eof() || s.is_error() {
                break;
            }
            let rc = unsafe { refill_stream(s) };
            if rc <= 0 {
                break;
            }
            let data2 = s.buffered_read(1);
            if data2.is_empty() {
                break;
            }
            data2[0]
        };

        unsafe { *buf.add(written) = byte as c_char };
        written += 1;
        if byte == b'\n' {
            break;
        }
    }

    if written == 0 {
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(10, max),
            true,
        );
        return std::ptr::null_mut();
    }

    // NUL-terminate.
    unsafe { *buf.add(written) = 0 };
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(10, written),
        false,
    );
    buf
}

/// POSIX `fputs`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fputs(s: *const c_char, stream: *mut c_void) -> c_int {
    if s.is_null() {
        return libc::EOF;
    }

    let id = stream as usize;
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        id,
        0,
        false,
        known_remaining(s as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return libc::EOF;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let bound = if repair {
        known_remaining(s as usize)
    } else {
        None
    };
    let (len, terminated) = unsafe { scan_c_str_len(s, bound) };
    if !terminated && repair {
        global_healing_policy().record(&HealingAction::TruncateWithNull {
            requested: bound.unwrap_or(len).saturating_add(1),
            truncated: len,
        });
    }

    let bytes = unsafe { std::slice::from_raw_parts(s as *const u8, len) };

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream_obj) = reg.streams.get_mut(&id) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return libc::EOF;
    };

    let flush_data = stream_obj.buffer_write(bytes);
    if !flush_data.is_empty() {
        let fd = stream_obj.fd();
        let rc = unsafe { sys_write_fd(fd, flush_data.as_ptr().cast(), flush_data.len()) };
        if rc >= 0 && rc as usize == flush_data.len() {
            stream_obj.mark_flushed();
        } else {
            stream_obj.set_error();
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(10, len),
                true,
            );
            return libc::EOF;
        }
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(10, len),
        false,
    );
    0
}

// ---------------------------------------------------------------------------
// fread / fwrite
// ---------------------------------------------------------------------------

/// POSIX `fread`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fread(
    ptr: *mut c_void,
    size: usize,
    nmemb: usize,
    stream: *mut c_void,
) -> usize {
    let total = size.saturating_mul(nmemb);
    if ptr.is_null() || total == 0 {
        return 0;
    }

    let id = stream as usize;
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, total, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return 0;
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return 0;
    };

    let dst = unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, total) };
    let mut read_total = 0usize;

    while read_total < total {
        let chunk = s.buffered_read(total - read_total);
        if !chunk.is_empty() {
            dst[read_total..read_total + chunk.len()].copy_from_slice(&chunk);
            read_total += chunk.len();
            continue;
        }
        if s.is_eof() || s.is_error() {
            break;
        }
        let rc = unsafe { refill_stream(s) };
        if rc <= 0 {
            break;
        }
    }

    let items = read_total.checked_div(size).unwrap_or(0);
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, read_total),
        items < nmemb,
    );
    items
}

/// POSIX `fwrite`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fwrite(
    ptr: *const c_void,
    size: usize,
    nmemb: usize,
    stream: *mut c_void,
) -> usize {
    let total = size.saturating_mul(nmemb);
    if ptr.is_null() || total == 0 {
        return 0;
    }

    let id = stream as usize;
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, total, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return 0;
    }

    let src = unsafe { std::slice::from_raw_parts(ptr as *const u8, total) };

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return 0;
    };

    let flush_data = s.buffer_write(src);
    if !flush_data.is_empty() {
        let fd = s.fd();
        let rc = unsafe { sys_write_fd(fd, flush_data.as_ptr().cast(), flush_data.len()) };
        if rc >= 0 && rc as usize == flush_data.len() {
            s.mark_flushed();
        } else {
            s.set_error();
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total),
                true,
            );
            return 0;
        }
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total),
        false,
    );
    nmemb
}

// ---------------------------------------------------------------------------
// fseek / ftell / rewind
// ---------------------------------------------------------------------------

/// POSIX `fseek`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fseek(stream: *mut c_void, offset: c_long, whence: c_int) -> c_int {
    let id = stream as usize;
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return -1;
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return -1;
    };

    // Flush pending writes and discard read buffer.
    let pending = s.prepare_seek();
    let fd = s.fd();
    if !pending.is_empty() {
        let rc = unsafe { sys_write_fd(fd, pending.as_ptr().cast(), pending.len()) };
        if rc < 0 || rc as usize != pending.len() {
            s.set_error();
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
            return -1;
        }
    }

    let new_off = unsafe { libc::syscall(libc::SYS_lseek as c_long, fd, offset, whence) as i64 };
    if new_off < 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    s.set_offset(new_off);
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, false);
    0
}

/// POSIX `ftell`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftell(stream: *mut c_void) -> c_long {
    let id = stream as usize;
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return -1;
    }

    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get(&id) else {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return -1;
    };

    let off = s.offset();
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
    off as c_long
}

/// POSIX `fseeko` — fseek with off_t offset (identical on LP64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fseeko(stream: *mut c_void, offset: i64, whence: c_int) -> c_int {
    unsafe { fseek(stream, offset as c_long, whence) }
}

/// POSIX `ftello` — ftell with off_t return (identical on LP64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftello(stream: *mut c_void) -> i64 {
    unsafe { ftell(stream) as i64 }
}

/// POSIX `rewind`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rewind(stream: *mut c_void) {
    // rewind is fseek(stream, 0, SEEK_SET) + clearerr.
    unsafe { fseek(stream, 0, libc::SEEK_SET) };

    let id = stream as usize;
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        s.clear_err();
    }
}

// ---------------------------------------------------------------------------
// feof / ferror / clearerr / ungetc / fileno
// ---------------------------------------------------------------------------

/// POSIX `feof`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feof(stream: *mut c_void) -> c_int {
    let id = stream as usize;
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get(&id) {
        if s.is_eof() { 1 } else { 0 }
    } else {
        0
    }
}

/// POSIX `ferror`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ferror(stream: *mut c_void) -> c_int {
    let id = stream as usize;
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get(&id) {
        if s.is_error() { 1 } else { 0 }
    } else {
        0
    }
}

/// POSIX `clearerr`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clearerr(stream: *mut c_void) {
    let id = stream as usize;
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        s.clear_err();
    }
}

/// POSIX `ungetc`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ungetc(c: c_int, stream: *mut c_void) -> c_int {
    if c == libc::EOF {
        return libc::EOF;
    }
    let id = stream as usize;
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        if s.ungetc(c as u8) { c } else { libc::EOF }
    } else {
        libc::EOF
    }
}

/// POSIX `fileno`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fileno(stream: *mut c_void) -> c_int {
    let id = stream as usize;
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get(&id) {
        s.fd()
    } else {
        unsafe { set_abi_errno(errno::EBADF) };
        -1
    }
}

// ---------------------------------------------------------------------------
// setvbuf / setbuf
// ---------------------------------------------------------------------------

/// POSIX `setvbuf`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setvbuf(
    stream: *mut c_void,
    _buf: *mut c_char,
    mode: c_int,
    size: usize,
) -> c_int {
    let Some(buf_mode) = BufMode::from_posix(mode) else {
        return -1;
    };

    let id = stream as usize;
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        // Note: we ignore the caller's buffer pointer; we always use internal allocation.
        if s.set_buffering(buf_mode, size) {
            0
        } else {
            -1
        }
    } else {
        -1
    }
}

/// POSIX `setbuf`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setbuf(stream: *mut c_void, buf: *mut c_char) {
    if buf.is_null() {
        unsafe {
            setvbuf(stream, std::ptr::null_mut(), 2 /* _IONBF */, 0)
        };
    } else {
        unsafe {
            setvbuf(stream, buf, 0 /* _IOFBF */, 8192)
        };
    }
}

// ---------------------------------------------------------------------------
// putchar / puts / getchar (preserved from bootstrap)
// ---------------------------------------------------------------------------

/// POSIX `putchar`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putchar(c: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, 1, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    }

    let byte = c as u8;
    let rc = unsafe { sys_write_fd(libc::STDOUT_FILENO, (&byte as *const u8).cast(), 1) };
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, rc != 1);
    if rc == 1 { byte as c_int } else { libc::EOF }
}

/// POSIX `puts`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    if s.is_null() {
        return libc::EOF;
    }

    let (mode, decision) = runtime_policy::decide(ApiFamily::Stdio, s as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return libc::EOF;
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let (len, terminated) = unsafe { scan_c_str_len(s, None) };
    if !terminated && repair {
        global_healing_policy().record(&HealingAction::TruncateWithNull {
            requested: len.saturating_add(1),
            truncated: len,
        });
    }

    let rc_body = unsafe { sys_write_fd(libc::STDOUT_FILENO, s.cast(), len) };
    let newline = [b'\n'];
    let rc_nl = unsafe { sys_write_fd(libc::STDOUT_FILENO, newline.as_ptr().cast(), 1) };
    let adverse = rc_body < 0 || rc_nl != 1 || (!terminated && repair);
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(10, len.saturating_add(1)),
        adverse,
    );

    if rc_body < 0 || rc_nl != 1 {
        libc::EOF
    } else {
        0
    }
}

/// POSIX `getchar`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getchar() -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, 1, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    }

    let mut byte = [0_u8; 1];
    let rc = unsafe { sys_read_fd(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) };
    let adverse = rc != 1;
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, adverse);
    if adverse { libc::EOF } else { byte[0] as c_int }
}

// ---------------------------------------------------------------------------
// perror
// ---------------------------------------------------------------------------

/// POSIX `perror`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn perror(s: *const c_char) {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return;
    }

    // Get current errno and map to message.
    let err = unsafe { *super::errno_abi::__errno_location() };
    let msg: &[u8] = match err {
        errno::EPERM => b"Operation not permitted",
        errno::ENOENT => b"No such file or directory",
        errno::ESRCH => b"No such process",
        errno::EINTR => b"Interrupted system call",
        errno::EIO => b"Input/output error",
        errno::ENXIO => b"No such device or address",
        errno::EBADF => b"Bad file descriptor",
        errno::ENOMEM => b"Cannot allocate memory",
        errno::EACCES => b"Permission denied",
        errno::EFAULT => b"Bad address",
        errno::EEXIST => b"File exists",
        errno::ENOTDIR => b"Not a directory",
        errno::EISDIR => b"Is a directory",
        errno::EINVAL => b"Invalid argument",
        errno::ENFILE => b"Too many open files in system",
        errno::EMFILE => b"Too many open files",
        errno::ENOSPC => b"No space left on device",
        errno::ESPIPE => b"Illegal seek",
        errno::EROFS => b"Read-only file system",
        errno::EPIPE => b"Broken pipe",
        errno::ERANGE => b"Numerical result out of range",
        errno::ENOSYS => b"Function not implemented",
        _ => b"Unknown error",
    };

    if !s.is_null() {
        let prefix = unsafe { CStr::from_ptr(s) }.to_bytes();
        if !prefix.is_empty() {
            let _ =
                unsafe { sys_write_fd(libc::STDERR_FILENO, prefix.as_ptr().cast(), prefix.len()) };
            let _ = unsafe { sys_write_fd(libc::STDERR_FILENO, b": ".as_ptr().cast(), 2) };
        }
    }

    let _ = unsafe { sys_write_fd(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len()) };
    let _ = unsafe { sys_write_fd(libc::STDERR_FILENO, b"\n".as_ptr().cast(), 1) };

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, false);
}

// ---------------------------------------------------------------------------
// printf / fprintf / sprintf / snprintf
// ---------------------------------------------------------------------------

use frankenlibc_core::stdio::{
    FormatSegment, LengthMod, Precision, Width, format_char, format_float, format_pointer,
    format_signed, format_str, format_unsigned, parse_format_string,
};

/// Maximum variadic arguments we extract per printf call.
const MAX_VA_ARGS: usize = 32;

/// Count how many variadic arguments a parsed format string needs.
fn count_printf_args(segments: &[FormatSegment<'_>]) -> usize {
    let mut needed = 0usize;
    for seg in segments {
        if let FormatSegment::Spec(spec) = seg {
            if matches!(spec.width, Width::FromArg) {
                needed += 1;
            }
            if matches!(spec.precision, Precision::FromArg) {
                needed += 1;
            }
            match spec.conversion {
                b'%' => {}
                _ => needed += 1,
            }
        }
    }
    needed.min(MAX_VA_ARGS)
}

/// Extract variadic arguments from `$args` into `$buf`, guided by `$segments`.
/// Uses a macro to avoid naming the unstable `VaListImpl` type directly.
macro_rules! extract_va_args {
    ($segments:expr, $args:expr, $buf:expr, $extract_count:expr) => {{
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

/// Internal: render a parsed format string with a raw argument pointer array.
///
/// `args` is a pointer to a contiguous array of `u64` values that were pushed
/// by the caller (the variadic ABI promotes smaller types to at least register width).
/// We interpret each value according to the format spec's conversion and length modifier.
///
/// Returns the formatted byte vector.
unsafe fn render_printf(fmt: &[u8], args: *const u64, max_args: usize) -> Vec<u8> {
    let segments = parse_format_string(fmt);
    let mut buf = Vec::with_capacity(256);
    let mut arg_idx = 0usize;

    for seg in &segments {
        match seg {
            FormatSegment::Literal(lit) => buf.extend_from_slice(lit),
            FormatSegment::Percent => buf.push(b'%'),
            FormatSegment::Spec(spec) => {
                // Resolve width from args if needed.
                let mut resolved_spec = spec.clone();
                if matches!(spec.width, Width::FromArg) {
                    if arg_idx < max_args {
                        let w = unsafe { *args.add(arg_idx) } as i64;
                        arg_idx += 1;
                        if w < 0 {
                            resolved_spec.flags.left_justify = true;
                            resolved_spec.width = Width::Fixed((-w) as usize);
                        } else {
                            resolved_spec.width = Width::Fixed(w as usize);
                        }
                    } else {
                        resolved_spec.width = Width::None;
                    }
                }
                if matches!(spec.precision, Precision::FromArg) {
                    if arg_idx < max_args {
                        let p = unsafe { *args.add(arg_idx) } as i64;
                        arg_idx += 1;
                        resolved_spec.precision = if p < 0 {
                            Precision::None
                        } else {
                            Precision::Fixed(p as usize)
                        };
                    } else {
                        resolved_spec.precision = Precision::None;
                    }
                }

                // Consume one argument for the conversion.
                match spec.conversion {
                    b'%' => buf.push(b'%'),
                    b'n' => {
                        // %n: store count of bytes written so far.
                        if arg_idx < max_args {
                            let ptr_val = unsafe { *args.add(arg_idx) } as usize;
                            arg_idx += 1;
                            if ptr_val != 0 {
                                let count = buf.len() as i32;
                                unsafe {
                                    *(ptr_val as *mut i32) = count;
                                }
                            }
                        }
                    }
                    b'd' | b'i' => {
                        if arg_idx < max_args {
                            let raw = unsafe { *args.add(arg_idx) };
                            arg_idx += 1;
                            let val = match spec.length {
                                LengthMod::Hh => (raw as i8) as i64,
                                LengthMod::H => (raw as i16) as i64,
                                LengthMod::L | LengthMod::Ll | LengthMod::J => raw as i64,
                                _ => (raw as i32) as i64,
                            };
                            format_signed(val, &resolved_spec, &mut buf);
                        }
                    }
                    b'u' | b'x' | b'X' | b'o' => {
                        if arg_idx < max_args {
                            let raw = unsafe { *args.add(arg_idx) };
                            arg_idx += 1;
                            let val = match spec.length {
                                LengthMod::Hh => (raw as u8) as u64,
                                LengthMod::H => (raw as u16) as u64,
                                LengthMod::L | LengthMod::Ll | LengthMod::J | LengthMod::Z => raw,
                                _ => (raw as u32) as u64,
                            };
                            format_unsigned(val, &resolved_spec, &mut buf);
                        }
                    }
                    b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                        if arg_idx < max_args {
                            let raw = unsafe { *args.add(arg_idx) };
                            arg_idx += 1;
                            let val = f64::from_bits(raw);
                            format_float(val, &resolved_spec, &mut buf);
                        }
                    }
                    b'c' => {
                        if arg_idx < max_args {
                            let raw = unsafe { *args.add(arg_idx) };
                            arg_idx += 1;
                            format_char(raw as u8, &resolved_spec, &mut buf);
                        }
                    }
                    b's' => {
                        if arg_idx < max_args {
                            let raw = unsafe { *args.add(arg_idx) };
                            arg_idx += 1;
                            let ptr = raw as usize as *const u8;
                            if ptr.is_null() {
                                format_str(b"(null)", &resolved_spec, &mut buf);
                            } else {
                                let s_bytes =
                                    unsafe { CStr::from_ptr(ptr as *const c_char) }.to_bytes();
                                format_str(s_bytes, &resolved_spec, &mut buf);
                            }
                        }
                    }
                    b'p' => {
                        if arg_idx < max_args {
                            let raw = unsafe { *args.add(arg_idx) };
                            arg_idx += 1;
                            format_pointer(raw as usize, &resolved_spec, &mut buf);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    buf
}

/// POSIX `snprintf` — format at most `size` bytes into `str`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn snprintf(
    str_buf: *mut c_char,
    size: usize,
    format: *const c_char,
    mut args: ...
) -> c_int {
    if format.is_null() {
        return -1;
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, size, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    if !str_buf.is_null() && size > 0 {
        let copy_len = total_len.min(size - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(rendered.as_ptr(), str_buf as *mut u8, copy_len);
            *str_buf.add(copy_len) = 0;
        }
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        false,
    );
    total_len as c_int
}

/// POSIX `sprintf`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sprintf(
    str_buf: *mut c_char,
    format: *const c_char,
    mut args: ...
) -> c_int {
    if format.is_null() || str_buf.is_null() {
        return -1;
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    unsafe {
        std::ptr::copy_nonoverlapping(rendered.as_ptr(), str_buf as *mut u8, total_len);
        *str_buf.add(total_len) = 0;
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        false,
    );
    total_len as c_int
}

/// POSIX `fprintf`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fprintf(
    stream: *mut c_void,
    format: *const c_char,
    mut args: ...
) -> c_int {
    if format.is_null() {
        return -1;
    }
    let id = stream as usize;

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        let flush_data = s.buffer_write(&rendered);
        if !flush_data.is_empty() {
            let fd = s.fd();
            let rc = unsafe { sys_write_fd(fd, flush_data.as_ptr().cast(), flush_data.len()) };
            if rc >= 0 && rc as usize == flush_data.len() {
                s.mark_flushed();
            } else {
                s.set_error();
                runtime_policy::observe(
                    ApiFamily::Stdio,
                    decision.profile,
                    runtime_policy::scaled_cost(15, total_len),
                    true,
                );
                return -1;
            }
        }
    } else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        false,
    );
    total_len as c_int
}

/// POSIX `printf`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn printf(format: *const c_char, mut args: ...) -> c_int {
    if format.is_null() {
        return -1;
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let rc = unsafe { sys_write_fd(libc::STDOUT_FILENO, rendered.as_ptr().cast(), total_len) };
    let adverse = rc < 0 || rc as usize != total_len;
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        adverse,
    );
    if adverse { -1 } else { total_len as c_int }
}

/// POSIX `dprintf`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dprintf(fd: c_int, format: *const c_char, mut args: ...) -> c_int {
    if format.is_null() {
        return -1;
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, fd as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let rc = unsafe { sys_write_fd(fd, rendered.as_ptr().cast(), total_len) };
    let adverse = rc < 0 || rc as usize != total_len;
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        adverse,
    );
    if adverse { -1 } else { total_len as c_int }
}

/// GNU `asprintf`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn asprintf(
    strp: *mut *mut c_char,
    format: *const c_char,
    mut args: ...
) -> c_int {
    if strp.is_null() || format.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    // SAFETY: caller provided non-null out-pointer.
    unsafe { *strp = std::ptr::null_mut() };

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, strp as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();
    let alloc_size = total_len.saturating_add(1);

    // SAFETY: allocation size is computed from rendered payload and includes trailing NUL byte.
    let out = unsafe { malloc(alloc_size).cast::<c_char>() };
    if out.is_null() {
        unsafe { set_abi_errno(errno::ENOMEM) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(rendered.as_ptr(), out.cast::<u8>(), total_len);
        *out.add(total_len) = 0;
        *strp = out;
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        false,
    );
    total_len as c_int
}

// ===========================================================================
// v*printf family — va_list variants (GlibcCallThrough)
//
// These delegate to glibc because Rust cannot safely extract arguments from
// a foreign va_list without naming the unstable VaListImpl type.
// The libc crate doesn't expose v*printf, so we link directly.
// ===========================================================================

unsafe extern "C" {
    #[link_name = "vsnprintf"]
    fn libc_vsnprintf(s: *mut c_char, n: usize, fmt: *const c_char, ap: *mut c_void) -> c_int;
    #[link_name = "vsprintf"]
    fn libc_vsprintf(s: *mut c_char, fmt: *const c_char, ap: *mut c_void) -> c_int;
    #[link_name = "vfprintf"]
    fn libc_vfprintf(stream: *mut c_void, fmt: *const c_char, ap: *mut c_void) -> c_int;
    #[link_name = "vprintf"]
    fn libc_vprintf(fmt: *const c_char, ap: *mut c_void) -> c_int;
    #[link_name = "vdprintf"]
    fn libc_vdprintf(fd: c_int, fmt: *const c_char, ap: *mut c_void) -> c_int;
    #[link_name = "vasprintf"]
    fn libc_vasprintf(strp: *mut *mut c_char, fmt: *const c_char, ap: *mut c_void) -> c_int;
}

/// POSIX `vsnprintf` — format at most `size` bytes from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vsnprintf(
    str_buf: *mut c_char,
    size: usize,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { libc_vsnprintf(str_buf, size, format, ap) }
}

/// POSIX `vsprintf` — format into buffer from va_list (no size limit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vsprintf(
    str_buf: *mut c_char,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { libc_vsprintf(str_buf, format, ap) }
}

/// POSIX `vfprintf` — format to stream from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vfprintf(
    stream: *mut c_void,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { libc_vfprintf(stream, format, ap) }
}

/// POSIX `vprintf` — format to stdout from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vprintf(format: *const c_char, ap: *mut c_void) -> c_int {
    unsafe { libc_vprintf(format, ap) }
}

/// POSIX `vdprintf` — format to file descriptor from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vdprintf(fd: c_int, format: *const c_char, ap: *mut c_void) -> c_int {
    unsafe { libc_vdprintf(fd, format, ap) }
}

/// GNU `vasprintf` — allocate and format from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vasprintf(
    strp: *mut *mut c_char,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { libc_vasprintf(strp, format, ap) }
}

// ===========================================================================
// scanf family — GlibcCallThrough
//
// Like v*printf, scanf functions need va_list handling that Rust cannot do
// natively. We link directly to glibc's v*scanf and forward the va_list.
// ===========================================================================

unsafe extern "C" {
    #[link_name = "vsscanf"]
    fn libc_vsscanf(s: *const c_char, fmt: *const c_char, ap: *mut c_void) -> c_int;
    #[link_name = "vfscanf"]
    fn libc_vfscanf(stream: *mut c_void, fmt: *const c_char, ap: *mut c_void) -> c_int;
    #[link_name = "vscanf"]
    fn libc_vscanf(fmt: *const c_char, ap: *mut c_void) -> c_int;
}

/// POSIX `sscanf` — scan formatted input from string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sscanf(s: *const c_char, format: *const c_char, mut args: ...) -> c_int {
    unsafe { libc_vsscanf(s, format, (&mut args) as *mut _ as *mut c_void) }
}

/// POSIX `fscanf` — scan formatted input from stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fscanf(
    stream: *mut c_void,
    format: *const c_char,
    mut args: ...,
) -> c_int {
    unsafe { libc_vfscanf(stream, format, (&mut args) as *mut _ as *mut c_void) }
}

/// POSIX `scanf` — scan formatted input from stdin.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scanf(format: *const c_char, mut args: ...) -> c_int {
    unsafe { libc_vscanf(format, (&mut args) as *mut _ as *mut c_void) }
}

/// POSIX `vsscanf` — scan formatted input from string with va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vsscanf(
    s: *const c_char,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { libc_vsscanf(s, format, ap) }
}

/// POSIX `vfscanf` — scan formatted input from stream with va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vfscanf(
    stream: *mut c_void,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { libc_vfscanf(stream, format, ap) }
}

/// POSIX `vscanf` — scan formatted input from stdin with va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vscanf(format: *const c_char, ap: *mut c_void) -> c_int {
    unsafe { libc_vscanf(format, ap) }
}

/// glibc fortified `__printf_chk`.
#[unsafe(export_name = "__printf_chk")]
pub unsafe extern "C" fn printf_chk(_flag: c_int, format: *const c_char, mut args: ...) -> c_int {
    if format.is_null() {
        return -1;
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let rc = unsafe { sys_write_fd(libc::STDOUT_FILENO, rendered.as_ptr().cast(), total_len) };
    let adverse = rc < 0 || rc as usize != total_len;
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        adverse,
    );
    if adverse { -1 } else { total_len as c_int }
}

/// glibc fortified `__fprintf_chk`.
#[unsafe(export_name = "__fprintf_chk")]
pub unsafe extern "C" fn fprintf_chk(
    stream: *mut c_void,
    _flag: c_int,
    format: *const c_char,
    mut args: ...
) -> c_int {
    if format.is_null() {
        return -1;
    }
    let id = stream as usize;

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        let flush_data = s.buffer_write(&rendered);
        if !flush_data.is_empty() {
            let fd = s.fd();
            let rc = unsafe { sys_write_fd(fd, flush_data.as_ptr().cast(), flush_data.len()) };
            if rc >= 0 && rc as usize == flush_data.len() {
                s.mark_flushed();
            } else {
                s.set_error();
                runtime_policy::observe(
                    ApiFamily::Stdio,
                    decision.profile,
                    runtime_policy::scaled_cost(15, total_len),
                    true,
                );
                return -1;
            }
        }
    } else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        false,
    );
    total_len as c_int
}

/// glibc fortified `__sprintf_chk`.
#[unsafe(export_name = "__sprintf_chk")]
pub unsafe extern "C" fn sprintf_chk(
    str_buf: *mut c_char,
    _flag: c_int,
    slen: usize,
    format: *const c_char,
    mut args: ...
) -> c_int {
    if format.is_null() || str_buf.is_null() || slen == 0 {
        return -1;
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, slen, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();
    let copy_len = total_len.min(slen.saturating_sub(1));

    unsafe {
        std::ptr::copy_nonoverlapping(rendered.as_ptr(), str_buf as *mut u8, copy_len);
        *str_buf.add(copy_len) = 0;
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        copy_len != total_len,
    );
    total_len as c_int
}

// ---------------------------------------------------------------------------
// getc / putc (function versions of fgetc / fputc)
// ---------------------------------------------------------------------------

/// POSIX `getc` — identical to `fgetc` but as a function (not macro).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getc(stream: *mut c_void) -> c_int {
    unsafe { fgetc(stream) }
}

/// POSIX `putc` — identical to `fputc` but as a function (not macro).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putc(c: c_int, stream: *mut c_void) -> c_int {
    unsafe { fputc(c, stream) }
}

// ---------------------------------------------------------------------------
// fgetpos / fsetpos
// ---------------------------------------------------------------------------

/// POSIX `fgetpos` — save the current stream position.
///
/// Stores the current value of the stream's file position into `*pos`.
/// Returns 0 on success, -1 on error with errno set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpos(stream: *mut c_void, pos: *mut libc::fpos_t) -> c_int {
    if stream.is_null() || pos.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let id = stream as usize;
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return -1;
    }

    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get(&id) else {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return -1;
    };

    // fpos_t is opaque; we store the offset as i64 at the start of the struct.
    // On Linux x86_64, fpos_t starts with __pos: i64.
    let offset = s.offset();
    // SAFETY: pos is non-null and points to a valid fpos_t; we write the
    // offset into the first 8 bytes which correspond to the __pos field.
    unsafe {
        std::ptr::write(pos as *mut i64, offset);
    }

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
    0
}

/// POSIX `fsetpos` — restore a previously saved stream position.
///
/// Restores the file position from `*pos` (previously set by `fgetpos`).
/// Returns 0 on success, -1 on error with errno set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsetpos(stream: *mut c_void, pos: *const libc::fpos_t) -> c_int {
    if stream.is_null() || pos.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    // Read the offset from the fpos_t (first 8 bytes = __pos field).
    let offset = unsafe { std::ptr::read(pos as *const i64) };

    // Delegate to fseek with SEEK_SET.
    unsafe { fseek(stream, offset as c_long, libc::SEEK_SET) }
}

// ---------------------------------------------------------------------------
// fdopen
// ---------------------------------------------------------------------------

/// POSIX `fdopen` — associate a FILE stream with an existing file descriptor.
///
/// The mode string must be compatible with the fd's open mode.
/// The fd is NOT duplicated — the stream takes ownership for buffering/close.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdopen(fd: c_int, mode: *const c_char) -> *mut c_void {
    if fd < 0 || mode.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, fd as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    let mode_bytes = unsafe { CStr::from_ptr(mode) }.to_bytes();
    let Some(open_flags) = parse_mode(mode_bytes) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return std::ptr::null_mut();
    };

    let stream = StdioStream::new(fd, open_flags);
    let id = alloc_stream_id();
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.insert(id, stream);

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, false);
    id as *mut c_void
}

// ---------------------------------------------------------------------------
// freopen
// ---------------------------------------------------------------------------

/// POSIX `freopen` — reopen a stream with a new file.
///
/// Closes the existing stream and opens a new file with the given mode.
/// If pathname is NULL, attempts to change the mode of the existing fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn freopen(
    pathname: *const c_char,
    mode: *const c_char,
    stream: *mut c_void,
) -> *mut c_void {
    if mode.is_null() || stream.is_null() {
        return std::ptr::null_mut();
    }

    let id = stream as usize;
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return std::ptr::null_mut();
    }

    let mode_bytes = unsafe { CStr::from_ptr(mode) }.to_bytes();
    let Some(open_flags) = parse_mode(mode_bytes) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return std::ptr::null_mut();
    };

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());

    // Close the old stream.
    if let Some(mut old) = reg.streams.remove(&id) {
        let pending = old.prepare_close();
        let old_fd = old.fd();
        if !pending.is_empty() && old_fd >= 0 {
            unsafe { sys_write_fd(old_fd, pending.as_ptr().cast(), pending.len()) };
        }
        // Close old fd unless it's a sentinel.
        if old_fd >= 0 && id != STDIN_SENTINEL && id != STDOUT_SENTINEL && id != STDERR_SENTINEL {
            unsafe { libc::syscall(libc::SYS_close as c_long, old_fd) };
        }
    }

    if pathname.is_null() {
        // NULL pathname: mode change only is not well-supported; return NULL.
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return std::ptr::null_mut();
    }

    // Open the new file.
    let oflags = flags_to_oflags(&open_flags);
    let create_mode: libc::mode_t = 0o666;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat as c_long,
            libc::AT_FDCWD,
            pathname,
            oflags,
            create_mode,
        ) as c_int
    };

    if fd < 0 {
        unsafe { set_abi_errno(errno::ENOENT) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 30, true);
        return std::ptr::null_mut();
    }

    let new_stream = StdioStream::new(fd, open_flags);
    reg.streams.insert(id, new_stream);

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 30, false);
    id as *mut c_void
}

// ---------------------------------------------------------------------------
// remove / rename
// ---------------------------------------------------------------------------

/// POSIX `remove` — remove a file or directory.
///
/// Equivalent to `unlink` for files and `rmdir` for directories.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remove(pathname: *const c_char) -> c_int {
    if pathname.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return -1;
    }

    // Try unlink first; if EISDIR, try rmdir.
    let ret =
        unsafe { libc::syscall(libc::SYS_unlinkat as c_long, libc::AT_FDCWD, pathname, 0) };
    if ret == 0 {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, false);
        return 0;
    }

    // Check if it's a directory.
    let errno_val = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(errno::EIO);
    if errno_val == errno::EISDIR {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_unlinkat as c_long,
                libc::AT_FDCWD,
                pathname,
                libc::AT_REMOVEDIR,
            )
        };
        if ret == 0 {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, false);
            return 0;
        }
    }

    let final_errno = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(errno::EIO);
    unsafe { set_abi_errno(final_errno) };
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
    -1
}

// ---------------------------------------------------------------------------
// getdelim / getline
// ---------------------------------------------------------------------------

/// POSIX `getdelim` — read until a delimiter, dynamically allocating the buffer.
///
/// Reads from `stream` until `delim` is found or EOF. Dynamically (re)allocates
/// `*lineptr` using `malloc`/`realloc`. Stores the line length in `*n`.
/// Returns the number of bytes read (including delim), or -1 on error/EOF.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdelim(
    lineptr: *mut *mut c_char,
    n: *mut usize,
    delim: c_int,
    stream: *mut c_void,
) -> isize {
    if lineptr.is_null() || n.is_null() || stream.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let id = stream as usize;
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let delim_byte = delim as u8;
    let mut buf: Vec<u8> = Vec::with_capacity(128);
    let mut got_delim = false;
    let mut got_any = false;

    // Read character by character using fgetc.
    loop {
        let ch = unsafe { fgetc(stream) };
        if ch == libc::EOF {
            break;
        }
        got_any = true;
        buf.push(ch as u8);
        if ch as u8 == delim_byte {
            got_delim = true;
            break;
        }
    }

    if !got_any {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    // Allocate/reallocate the output buffer.
    let needed = buf.len() + 1; // +1 for NUL terminator
    let current_buf = unsafe { *lineptr };
    let current_size = unsafe { *n };

    let out_buf = if current_buf.is_null() || current_size < needed {
        let new_size = needed.max(128);
        let new_buf = unsafe { crate::malloc_abi::realloc(current_buf.cast(), new_size) };
        if new_buf.is_null() {
            unsafe { set_abi_errno(errno::ENOMEM) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
            return -1;
        }
        unsafe { *lineptr = new_buf.cast() };
        unsafe { *n = new_size };
        new_buf as *mut u8
    } else {
        current_buf as *mut u8
    };

    // Copy data to output buffer.
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), out_buf, buf.len());
        *out_buf.add(buf.len()) = 0; // NUL terminate
    }

    let _ = got_delim; // suppress unused warning
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, false);
    buf.len() as isize
}

/// POSIX `getline` — read a complete line, dynamically allocating the buffer.
///
/// Equivalent to `getdelim(lineptr, n, '\n', stream)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getline(
    lineptr: *mut *mut c_char,
    n: *mut usize,
    stream: *mut c_void,
) -> isize {
    unsafe { getdelim(lineptr, n, b'\n' as c_int, stream) }
}

// ---------------------------------------------------------------------------
// tmpfile / tmpnam
// ---------------------------------------------------------------------------

/// POSIX `tmpfile` — create a temporary file opened for update.
///
/// Creates and opens a temporary file that is automatically removed when closed.
/// Returns a FILE stream pointer or NULL on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tmpfile() -> *mut c_void {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 20, true);
        return std::ptr::null_mut();
    }

    // Use O_TMPFILE for efficient temporary file creation.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat as c_long,
            libc::AT_FDCWD,
            c"/tmp".as_ptr(),
            libc::O_RDWR | libc::O_TMPFILE | libc::O_EXCL,
            0o600 as libc::mode_t,
        ) as c_int
    };

    if fd < 0 {
        // Fallback: create a named temp file and unlink it.
        let template = b"/tmp/frankenlibc_XXXXXX\0";
        let mut path = *template;
        let fd2 = unsafe { libc::mkstemp(path.as_mut_ptr().cast()) };
        if fd2 < 0 {
            let e = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(errno::EIO);
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 20, true);
            return std::ptr::null_mut();
        }
        // Unlink immediately so it's deleted on close.
        unsafe { libc::syscall(libc::SYS_unlinkat as c_long, libc::AT_FDCWD, path.as_ptr(), 0) };

        let open_flags = OpenFlags {
            readable: true,
            writable: true,
            ..Default::default()
        };
        let stream = StdioStream::new(fd2, open_flags);
        let id = alloc_stream_id();
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        reg.streams.insert(id, stream);
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 20, false);
        return id as *mut c_void;
    }

    let open_flags = OpenFlags {
        readable: true,
        writable: true,
        ..Default::default()
    };
    let stream = StdioStream::new(fd, open_flags);
    let id = alloc_stream_id();
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.insert(id, stream);

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 20, false);
    id as *mut c_void
}

/// Thread-local counter for tmpnam uniqueness.
static TMPNAM_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// POSIX `tmpnam` — generate a unique temporary file name.
///
/// If `s` is not NULL, the name is written to the buffer pointed to by `s`
/// (which must be at least `L_tmpnam` bytes). If `s` is NULL, a static
/// buffer is used (NOT thread-safe in that case).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tmpnam(s: *mut c_char) -> *mut c_char {
    thread_local! {
        static BUF: std::cell::UnsafeCell<[u8; 64]> = const { std::cell::UnsafeCell::new([0u8; 64]) };
    }

    let counter = TMPNAM_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = unsafe { libc::syscall(libc::SYS_getpid as c_long) } as u32;

    // Format: /tmp/flc_<pid>_<counter>
    let mut name = [0u8; 48];
    let prefix = b"/tmp/flc_";
    let prefix_len = prefix.len();
    name[..prefix_len].copy_from_slice(prefix);

    let mut pos = prefix_len;
    // Write pid.
    pos = write_u32_to_buf(&mut name, pos, pid);
    name[pos] = b'_';
    pos += 1;
    // Write counter.
    pos = write_u64_to_buf(&mut name, pos, counter);
    name[pos] = 0; // NUL

    let total = pos + 1;

    if !s.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(name.as_ptr(), s as *mut u8, total) };
        s
    } else {
        BUF.with(|cell| {
            let buf = cell.get();
            unsafe {
                std::ptr::copy_nonoverlapping(name.as_ptr(), (*buf).as_mut_ptr(), total);
                (*buf).as_ptr() as *mut c_char
            }
        })
    }
}

/// Write a u32 as decimal digits into `buf` starting at `start`. Returns the new position.
fn write_u32_to_buf(buf: &mut [u8], start: usize, mut v: u32) -> usize {
    if v == 0 {
        buf[start] = b'0';
        return start + 1;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while v > 0 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    // Reverse into buf.
    for i in 0..len {
        buf[start + i] = tmp[len - 1 - i];
    }
    start + len
}

/// Write a u64 as decimal digits into `buf` starting at `start`. Returns the new position.
fn write_u64_to_buf(buf: &mut [u8], start: usize, mut v: u64) -> usize {
    if v == 0 {
        buf[start] = b'0';
        return start + 1;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0;
    while v > 0 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        buf[start + i] = tmp[len - 1 - i];
    }
    start + len
}

// ---------------------------------------------------------------------------
// popen / pclose
// ---------------------------------------------------------------------------

/// Registry to map FILE* sentinels to child PIDs for pclose.
static POPEN_PIDS: Mutex<Option<HashMap<usize, i32>>> = Mutex::new(None);

/// POSIX `popen` — open a process by creating a pipe.
///
/// Forks and execs `/bin/sh -c command`. If type is `"r"`, returns a stream
/// that reads from the child's stdout. If `"w"`, returns a stream that writes
/// to the child's stdin.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn popen(command: *const c_char, typ: *const c_char) -> *mut c_void {
    if command.is_null() || typ.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
        return std::ptr::null_mut();
    }

    let mode = unsafe { *typ as u8 };
    let reading = mode == b'r';
    if mode != b'r' && mode != b'w' {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
        return std::ptr::null_mut();
    }

    // Create pipe: pipe_fds[0] = read end, pipe_fds[1] = write end.
    let mut pipe_fds = [0i32; 2];
    let ret = unsafe { libc::syscall(libc::SYS_pipe2 as c_long, pipe_fds.as_mut_ptr(), 0) };
    if ret < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EIO);
        unsafe { set_abi_errno(e) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
        return std::ptr::null_mut();
    }

    // Fork via clone(SIGCHLD).
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone as c_long,
            libc::SIGCHLD as c_long,
            0 as c_long,
            0 as c_long,
            0 as c_long,
            0 as c_long,
        ) as i32
    };

    if pid < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::ENOMEM);
        unsafe { set_abi_errno(e) };
        unsafe {
            libc::syscall(libc::SYS_close as c_long, pipe_fds[0]);
            libc::syscall(libc::SYS_close as c_long, pipe_fds[1]);
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
        return std::ptr::null_mut();
    }

    if pid == 0 {
        // Child process.
        if reading {
            // Parent reads from child's stdout: dup write end to stdout.
            unsafe {
                libc::syscall(libc::SYS_close as c_long, pipe_fds[0]);
                libc::syscall(libc::SYS_dup2 as c_long, pipe_fds[1], libc::STDOUT_FILENO);
                libc::syscall(libc::SYS_close as c_long, pipe_fds[1]);
            }
        } else {
            // Parent writes to child's stdin: dup read end to stdin.
            unsafe {
                libc::syscall(libc::SYS_close as c_long, pipe_fds[1]);
                libc::syscall(libc::SYS_dup2 as c_long, pipe_fds[0], libc::STDIN_FILENO);
                libc::syscall(libc::SYS_close as c_long, pipe_fds[0]);
            }
        }

        let sh = c"/bin/sh".as_ptr();
        let dash_c = c"-c".as_ptr();
        let argv: [*const c_char; 4] = [sh, dash_c, command, std::ptr::null()];
        unsafe {
            libc::syscall(
                libc::SYS_execve as c_long,
                sh,
                argv.as_ptr(),
                std::ptr::null::<*const c_char>(),
            );
            libc::syscall(libc::SYS_exit_group as c_long, 127 as c_long);
        }
        unsafe { std::hint::unreachable_unchecked() }
    }

    // Parent: close unused end and wrap the other in a FILE stream.
    let our_fd = if reading {
        unsafe { libc::syscall(libc::SYS_close as c_long, pipe_fds[1]) };
        pipe_fds[0]
    } else {
        unsafe { libc::syscall(libc::SYS_close as c_long, pipe_fds[0]) };
        pipe_fds[1]
    };

    let open_flags = OpenFlags {
        readable: reading,
        writable: !reading,
        ..Default::default()
    };
    let stream = StdioStream::new(our_fd, open_flags);
    let id = alloc_stream_id();
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.insert(id, stream);
    drop(reg);

    // Record the child PID so pclose can wait for it.
    let mut pids = POPEN_PIDS.lock().unwrap_or_else(|e| e.into_inner());
    pids.get_or_insert_with(HashMap::new).insert(id, pid);

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, false);
    id as *mut c_void
}

/// POSIX `pclose` — close a stream opened by popen and wait for the child.
///
/// Returns the child's exit status, or -1 on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pclose(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let id = stream as usize;

    // Look up and remove the child PID.
    let child_pid = {
        let mut pids = POPEN_PIDS.lock().unwrap_or_else(|e| e.into_inner());
        pids.as_mut().and_then(|m| m.remove(&id))
    };

    let Some(pid) = child_pid else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    };

    // Close the stream (flushes and closes fd).
    unsafe { fclose(stream) };

    // Wait for child.
    let mut wstatus: c_int = 0;
    loop {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_wait4 as c_long,
                pid,
                &mut wstatus as *mut c_int,
                0,
                std::ptr::null::<c_void>(),
            )
        };
        if ret == pid as i64 {
            break;
        }
        if ret < 0 {
            let e = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINTR);
            if e != libc::EINTR {
                unsafe { set_abi_errno(e) };
                return -1;
            }
        }
    }

    wstatus
}

/// glibc fortified `__snprintf_chk`.
#[unsafe(export_name = "__snprintf_chk")]
pub unsafe extern "C" fn snprintf_chk(
    str_buf: *mut c_char,
    maxlen: usize,
    _flag: c_int,
    slen: usize,
    format: *const c_char,
    mut args: ...
) -> c_int {
    if format.is_null() || str_buf.is_null() {
        return -1;
    }

    let effective = maxlen.min(slen);
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, effective, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    if effective > 0 {
        let copy_len = total_len.min(effective - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(rendered.as_ptr(), str_buf as *mut u8, copy_len);
            *str_buf.add(copy_len) = 0;
        }
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        total_len >= effective,
    );
    total_len as c_int
}

// ---------------------------------------------------------------------------
// 64-bit aliases — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "fopen64"]
    fn libc_fopen64(pathname: *const c_char, mode: *const c_char) -> *mut c_void;
    #[link_name = "freopen64"]
    fn libc_freopen64(pathname: *const c_char, mode: *const c_char, stream: *mut c_void) -> *mut c_void;
    #[link_name = "tmpfile64"]
    fn libc_tmpfile64() -> *mut c_void;
    #[link_name = "fseeko64"]
    fn libc_fseeko64(stream: *mut c_void, offset: i64, whence: c_int) -> c_int;
    #[link_name = "ftello64"]
    fn libc_ftello64(stream: *mut c_void) -> i64;
    #[link_name = "fgetpos64"]
    fn libc_fgetpos64(stream: *mut c_void, pos: *mut c_void) -> c_int;
    #[link_name = "fsetpos64"]
    fn libc_fsetpos64(stream: *mut c_void, pos: *const c_void) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fopen64(pathname: *const c_char, mode: *const c_char) -> *mut c_void {
    unsafe { libc_fopen64(pathname, mode) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn freopen64(
    pathname: *const c_char,
    mode: *const c_char,
    stream: *mut c_void,
) -> *mut c_void {
    unsafe { libc_freopen64(pathname, mode, stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tmpfile64() -> *mut c_void {
    unsafe { libc_tmpfile64() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fseeko64(stream: *mut c_void, offset: i64, whence: c_int) -> c_int {
    unsafe { libc_fseeko64(stream, offset, whence) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftello64(stream: *mut c_void) -> i64 {
    unsafe { libc_ftello64(stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpos64(stream: *mut c_void, pos: *mut c_void) -> c_int {
    unsafe { libc_fgetpos64(stream, pos) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsetpos64(stream: *mut c_void, pos: *const c_void) -> c_int {
    unsafe { libc_fsetpos64(stream, pos) }
}
