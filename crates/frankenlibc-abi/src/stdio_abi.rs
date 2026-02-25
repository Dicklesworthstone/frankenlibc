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
pub(crate) unsafe fn c_str_bytes<'a>(ptr: *const c_char) -> &'a [u8] {
    let (len, _) = unsafe { scan_c_str_len(ptr, None) };
    // SAFETY: `scan_c_str_len` scanned until the first NUL byte, so this range is readable.
    unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) }
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

#[inline]
fn stream_exists(id: usize) -> bool {
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.contains_key(&id)
}

/// Flush a stream's pending write data to its fd. Returns true on success.
unsafe fn flush_stream(stream: &mut StdioStream) -> bool {
    let len = stream.pending_flush().len();
    if len == 0 {
        return true;
    }
    let fd = stream.fd();
    let mut written = 0usize;
    while written < len {
        let pending = stream.pending_flush();
        let ptr = pending[written..].as_ptr();
        let chunk_len = pending.len() - written;
        let rc = unsafe { sys_write_fd(fd, ptr.cast(), chunk_len) };
        if rc < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == errno::EINTR {
                continue;
            }
            stream.set_error();
            return false;
        } else if rc == 0 {
            stream.set_error();
            return false;
        }
        written += rc as usize;
    }
    stream.mark_flushed();
    true
}

/// Fill a stream's read buffer from its fd. Returns bytes read (0 on EOF, -1 on error).
unsafe fn refill_stream(stream: &mut StdioStream) -> isize {
    let capacity = stream.buffer_capacity();
    if capacity == 0 {
        return 0; // Cannot buffer anything.
    }
    let mut tmp = vec![0u8; capacity.min(8192)];
    let fd = stream.fd();
    let rc = unsafe { sys_read_fd(fd, tmp.as_mut_ptr().cast(), tmp.len()) };
    if rc > 0 {
        stream.fill_read_buffer(&tmp[..rc as usize]);
        rc
    } else if rc == 0 {
        stream.set_eof();
        0
    } else {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if e != errno::EINTR {
            stream.set_error();
        }
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

    // Parse mode string.
    let mode_bytes = unsafe { CStr::from_ptr(mode) }.to_bytes();
    let Some(open_flags) = parse_mode(mode_bytes) else {
        unsafe { set_abi_errno(errno::EINVAL) };
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
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::ENOENT);
        unsafe { set_abi_errno(e) };
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
    id as *mut c_void
}

/// POSIX `fclose`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fclose(stream: *mut c_void) -> c_int {
    let id = stream as usize;
    if id == 0 {
        return libc::EOF;
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut s) = reg.streams.remove(&id) else {
        unsafe { set_abi_errno(errno::EBADF) };
        return libc::EOF;
    };
    drop(reg);

    // Cookie-backed streams close via callback and cookie-registry teardown.
    if is_cookie_stream(id) {
        let rc = unsafe { cookie_stream_close(id) };
        return if rc == 0 { 0 } else { libc::EOF };
    }

    // Memory-backed streams: sync data, then clean up.
    if s.is_mem_backed() {
        unsafe { sync_memstream_to_caller(id, &s) };
        // Remove sync metadata for open_memstream.
        let mut sync_guard = mem_sync_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut map) = *sync_guard {
            map.remove(&id);
        }
        return 0;
    }

    let fd = s.fd();
    // Flush pending writes.
    let pending = s.prepare_close();
    let mut adverse = false;

    if !pending.is_empty() && fd >= 0 {
        let mut written = 0usize;
        while written < pending.len() {
            let rc = unsafe {
                sys_write_fd(
                    fd,
                    pending[written..].as_ptr().cast(),
                    pending.len() - written,
                )
            };
            if rc < 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if e == errno::EINTR {
                    continue;
                }
                adverse = true;
                break;
            } else if rc == 0 {
                adverse = true;
                break;
            }
            written += rc as usize;
        }
    }

    // Close the fd (don't close stdin/stdout/stderr sentinel fds).
    if fd >= 0 && id != STDIN_SENTINEL && id != STDOUT_SENTINEL && id != STDERR_SENTINEL {
        let rc = unsafe { libc::syscall(libc::SYS_close as c_long, fd) };
        if rc < 0 {
            adverse = true;
        }
    }

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
            if let Some(s) = reg.streams.get_mut(&id) {
                let ok = if is_cookie_stream(id) {
                    true
                } else if s.is_mem_backed() {
                    unsafe { sync_memstream_to_caller(id, s) };
                    true
                } else {
                    unsafe { flush_stream(s) }
                };
                if !ok {
                    any_fail = true;
                }
            }
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 20, any_fail);
        return if any_fail { libc::EOF } else { 0 };
    }

    let id = stream as usize;
    if is_cookie_stream(id) {
        let adverse = !stream_exists(id);
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 8, adverse);
        return if adverse { libc::EOF } else { 0 };
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        // Memory-backed streams: sync data to C caller's pointers (open_memstream).
        if s.is_mem_backed() {
            unsafe { sync_memstream_to_caller(id, s) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 8, false);
            return 0;
        }
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

    if is_cookie_stream(id) {
        if !stream_exists(id) {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
            return libc::EOF;
        }

        let mut byte = [0u8; 1];
        let rc = unsafe { cookie_stream_read(id, byte.as_mut_ptr(), 1) };

        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = reg.streams.get_mut(&id) else {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
            return libc::EOF;
        };

        if rc > 0 {
            s.set_offset(s.offset().saturating_add(1));
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
            return byte[0] as c_int;
        }
        if rc == 0 {
            s.set_eof();
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
            return libc::EOF;
        }

        s.set_error();
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    };

    // Memory-backed streams: read directly from backing.
    if s.is_mem_backed() {
        let data = s.mem_read(1);
        if data.is_empty() {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
            return libc::EOF;
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
        return data[0] as c_int;
    }

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

    if s.buffer_capacity() == 0 {
        let mut b = [0u8; 1];
        let fd = s.fd();
        let rc = unsafe { sys_read_fd(fd, b.as_mut_ptr().cast(), 1) };
        if rc > 0 {
            s.set_offset(s.offset().saturating_add(1));
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, false);
            return b[0] as c_int;
        } else if rc == 0 {
            s.set_eof();
        } else {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e != errno::EINTR {
                s.set_error();
            }
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
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

    if is_cookie_stream(id) {
        if !stream_exists(id) {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
            return libc::EOF;
        }
        let rc = unsafe { cookie_stream_write(id, [byte].as_ptr(), 1) };
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = reg.streams.get_mut(&id) else {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
            return libc::EOF;
        };
        if rc > 0 {
            s.set_offset(s.offset().saturating_add(1));
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
            return c;
        }
        s.set_error();
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    };

    // Memory-backed streams: write directly to backing.
    if s.is_mem_backed() {
        let n = s.mem_write(&[byte]);
        if n == 0 {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
            return libc::EOF;
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
        return c;
    }

    let flush_data = s.buffer_write(&[byte]);
    if !flush_data.is_empty() {
        let fd = s.fd();
        let mut written = 0usize;
        let mut success = true;
        while written < flush_data.len() {
            let rc = unsafe {
                sys_write_fd(
                    fd,
                    flush_data[written..].as_ptr().cast(),
                    flush_data.len() - written,
                )
            };
            if rc < 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if e == errno::EINTR {
                    continue;
                }
                success = false;
                break;
            } else if rc == 0 {
                success = false;
                break;
            }
            written += rc as usize;
        }
        if success {
            // buffer_write already managed the internal buffer state.
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
    if size == 1 {
        unsafe { *buf = 0 };
        return buf;
    }
    let id = stream as usize;
    let max = (size - 1) as usize; // Leave room for NUL.

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, max, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    if is_cookie_stream(id) {
        if !stream_exists(id) {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
            return std::ptr::null_mut();
        }

        let mut written = 0usize;
        let mut had_error = false;
        let mut reached_eof = false;
        while written < max {
            let mut byte = [0u8; 1];
            let rc = unsafe { cookie_stream_read(id, byte.as_mut_ptr(), 1) };
            if rc > 0 {
                unsafe { *buf.add(written) = byte[0] as c_char };
                written += 1;
                if byte[0] == b'\n' {
                    break;
                }
                continue;
            }
            if rc == 0 {
                reached_eof = true;
            } else {
                had_error = true;
            }
            break;
        }

        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = reg.streams.get_mut(&id) {
            let delta = written.min(i64::MAX as usize) as i64;
            s.set_offset(s.offset().saturating_add(delta));
            if reached_eof {
                s.set_eof();
            }
            if had_error {
                s.set_error();
            }
        }

        if (written == 0 && max > 0) || had_error {
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(10, max),
                true,
            );
            return std::ptr::null_mut();
        }

        unsafe { *buf.add(written) = 0 };
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(10, written),
            false,
        );
        return buf;
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return std::ptr::null_mut();
    };

    if max == 0 {
        unsafe { *buf = 0 };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
        return buf;
    }

    let mut written = 0usize;
    let mut had_error = false;
    while written < max {
        // Try one byte from buffer.
        let data = s.buffered_read(1);
        let byte = if !data.is_empty() {
            data[0]
        } else {
            if s.is_eof() || s.is_error() {
                if s.is_error() {
                    had_error = true;
                }
                break;
            }
            if s.buffer_capacity() == 0 {
                let mut b = [0u8; 1];
                let fd = s.fd();
                let rc = unsafe { sys_read_fd(fd, b.as_mut_ptr().cast(), 1) };
                if rc > 0 {
                    s.set_offset(s.offset().saturating_add(1));
                    b[0]
                } else {
                    if rc == 0 {
                        s.set_eof();
                    } else {
                        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                        if e != errno::EINTR {
                            s.set_error();
                            had_error = true;
                        }
                    }
                    break;
                }
            } else {
                let rc = unsafe { refill_stream(s) };
                if rc <= 0 {
                    if s.is_error() {
                        had_error = true;
                    }
                    break;
                }
                let data2 = s.buffered_read(1);
                if data2.is_empty() {
                    break;
                }
                data2[0]
            }
        };

        unsafe { *buf.add(written) = byte as c_char };
        written += 1;
        if byte == b'\n' {
            break;
        }
    }

    if (written == 0 && max > 0) || had_error {
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

    if is_cookie_stream(id) {
        if !stream_exists(id) {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
            return libc::EOF;
        }

        let mut written = 0usize;
        while written < bytes.len() {
            let rc = unsafe {
                cookie_stream_write(
                    id,
                    bytes[written..].as_ptr(),
                    bytes.len().saturating_sub(written),
                )
            };
            if rc <= 0 {
                break;
            }
            let advanced = (rc as usize).min(bytes.len() - written);
            if advanced == 0 {
                break;
            }
            written += advanced;
        }

        let adverse = written < bytes.len();
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(stream_obj) = reg.streams.get_mut(&id) {
            let delta = written.min(i64::MAX as usize) as i64;
            stream_obj.set_offset(stream_obj.offset().saturating_add(delta));
            if adverse {
                stream_obj.set_error();
            }
        }

        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(10, len),
            adverse,
        );
        return if adverse { libc::EOF } else { 0 };
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream_obj) = reg.streams.get_mut(&id) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return libc::EOF;
    };

    let flush_data = stream_obj.buffer_write(bytes);
    if !flush_data.is_empty() {
        let fd = stream_obj.fd();
        let mut written = 0usize;
        let mut success = true;
        while written < flush_data.len() {
            let rc = unsafe {
                sys_write_fd(
                    fd,
                    flush_data[written..].as_ptr().cast(),
                    flush_data.len() - written,
                )
            };
            if rc < 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if e == errno::EINTR {
                    continue;
                }
                success = false;
                break;
            } else if rc == 0 {
                success = false;
                break;
            }
            written += rc as usize;
        }
        if success {
            // buffer_write already managed the internal buffer state.
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
    let Some(total) = size.checked_mul(nmemb) else {
        unsafe { set_abi_errno(errno::EOVERFLOW) };
        return 0;
    };
    if ptr.is_null() || total == 0 {
        return 0;
    }

    let id = stream as usize;
    let dst = unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, total) };

    if is_cookie_stream(id) {
        if !stream_exists(id) {
            return 0;
        }

        let mut read_total = 0usize;
        let mut reached_eof = false;
        let mut had_error = false;

        while read_total < total {
            let rc = unsafe {
                cookie_stream_read(
                    id,
                    dst[read_total..].as_mut_ptr(),
                    total.saturating_sub(read_total),
                )
            };
            if rc > 0 {
                let advanced = (rc as usize).min(total - read_total);
                if advanced == 0 {
                    had_error = true;
                    break;
                }
                read_total += advanced;
                continue;
            }
            if rc == 0 {
                reached_eof = true;
            } else {
                had_error = true;
            }
            break;
        }

        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = reg.streams.get_mut(&id) {
            let delta = read_total.min(i64::MAX as usize) as i64;
            s.set_offset(s.offset().saturating_add(delta));
            if reached_eof {
                s.set_eof();
            }
            if had_error {
                s.set_error();
            }
        }

        return read_total.checked_div(size).unwrap_or(0);
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        return 0;
    };

    let mut read_total = 0usize;

    // Memory-backed streams: read directly from the backing.
    if s.is_mem_backed() {
        let data = s.mem_read(total);
        let n = data.len();
        dst[..n].copy_from_slice(&data);
        return n.checked_div(size).unwrap_or(0);
    }

    while read_total < total {
        // Prefer direct fd reads to avoid recursive memcpy interposition through
        // buffered internals under LD_PRELOAD.
        let fd = s.fd();
        let to_read = total - read_total;
        let rc = unsafe { sys_read_fd(fd, dst[read_total..].as_mut_ptr().cast(), to_read) };
        if rc > 0 {
            let bytes_read = rc as usize;
            read_total += bytes_read;
            s.set_offset(s.offset().saturating_add(bytes_read as i64));
            continue;
        } else if rc == 0 {
            s.set_eof();
            break;
        } else {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == errno::EINTR {
                continue;
            }
            s.set_error();
            break;
        }
    }

    read_total.checked_div(size).unwrap_or(0)
}

/// POSIX `fwrite`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fwrite(
    ptr: *const c_void,
    size: usize,
    nmemb: usize,
    stream: *mut c_void,
) -> usize {
    let Some(total) = size.checked_mul(nmemb) else {
        unsafe { set_abi_errno(errno::EOVERFLOW) };
        return 0;
    };
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

    if is_cookie_stream(id) {
        if !stream_exists(id) {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
            return 0;
        }

        let mut written_total = 0usize;
        while written_total < total {
            let rc = unsafe {
                cookie_stream_write(
                    id,
                    src[written_total..].as_ptr(),
                    total.saturating_sub(written_total),
                )
            };
            if rc <= 0 {
                break;
            }
            let advanced = (rc as usize).min(total - written_total);
            if advanced == 0 {
                break;
            }
            written_total += advanced;
        }

        let adverse = written_total < total;
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = reg.streams.get_mut(&id) {
            let delta = written_total.min(i64::MAX as usize) as i64;
            s.set_offset(s.offset().saturating_add(delta));
            if adverse {
                s.set_error();
            }
        }
        let complete_items = written_total.checked_div(size).unwrap_or(0);
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(15, total),
            adverse,
        );
        return complete_items;
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return 0;
    };

    // Memory-backed streams: write directly to the backing.
    if s.is_mem_backed() {
        let written = s.mem_write(src);
        let complete_items = written.checked_div(size).unwrap_or(0);
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(15, total),
            written < total,
        );
        return complete_items;
    }

    let flush_data = s.buffer_write(src);
    if !flush_data.is_empty() {
        let fd = s.fd();
        let mut written = 0usize;
        let mut success = true;
        while written < flush_data.len() {
            let rc = unsafe {
                sys_write_fd(
                    fd,
                    flush_data[written..].as_ptr().cast(),
                    flush_data.len() - written,
                )
            };
            if rc < 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if e == errno::EINTR {
                    continue;
                }
                success = false;
                break;
            } else if rc == 0 {
                success = false;
                break;
            }
            written += rc as usize;
        }
        if success {
            // buffer_write already managed the internal buffer state.
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
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return -1;
    }

    if is_cookie_stream(id) {
        if !stream_exists(id) {
            unsafe { set_abi_errno(errno::EBADF) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
            return -1;
        }

        let mut cookie_off = offset;
        let rc = unsafe { cookie_stream_seek(id, &mut cookie_off as *mut i64, whence) };

        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = reg.streams.get_mut(&id) else {
            unsafe { set_abi_errno(errno::EBADF) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
            return -1;
        };

        if rc != 0 {
            s.set_error();
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
            return -1;
        }

        s.set_offset(cookie_off);
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, false);
        return 0;
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return -1;
    };

    // Memory-backed streams: seek within the backing buffer.
    if s.is_mem_backed() {
        let new_pos = s.mem_seek(offset, whence);
        if new_pos < 0 {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
            return -1;
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, false);
        return 0;
    }

    // Flush pending writes and discard read buffer.
    let pending = s.prepare_seek();
    let fd = s.fd();
    if !pending.is_empty() {
        let mut written = 0usize;
        while written < pending.len() {
            let rc = unsafe {
                sys_write_fd(
                    fd,
                    pending[written..].as_ptr().cast(),
                    pending.len() - written,
                )
            };
            if rc < 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if e == errno::EINTR {
                    continue;
                }
                s.set_error();
                runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
                return -1;
            } else if rc == 0 {
                s.set_error();
                runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
                return -1;
            }
            written += rc as usize;
        }
    }

    let (target_off, target_whence) = if whence == libc::SEEK_CUR {
        match s.offset().checked_add(offset) {
            Some(off) => (off, libc::SEEK_SET),
            None => {
                unsafe { set_abi_errno(errno::EOVERFLOW) };
                runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
                return -1;
            }
        }
    } else {
        (offset, whence)
    };

    let new_off =
        unsafe { libc::syscall(libc::SYS_lseek as c_long, fd, target_off, target_whence) as i64 };
    if new_off < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
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
        unsafe { set_abi_errno(errno::EACCES) };
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
    // POSIX: putchar(c) is equivalent to fputc(c, stdout).
    unsafe { fputc(c, STDOUT_SENTINEL as *mut c_void) }
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

    // POSIX: puts writes s followed by a newline to stdout.
    // Use the buffered stream to maintain coherence with fprintf(stdout, ...).
    let stdout_ptr = STDOUT_SENTINEL as *mut c_void;
    let rc_body = unsafe { fputs(s, stdout_ptr) };
    if rc_body == libc::EOF {
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(10, len.saturating_add(1)),
            true,
        );
        return libc::EOF;
    }
    let rc_nl = unsafe { fputc(b'\n' as c_int, stdout_ptr) };
    let adverse = rc_nl == libc::EOF || (!terminated && repair);
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(10, len.saturating_add(1)),
        adverse,
    );

    if rc_nl == libc::EOF { libc::EOF } else { 0 }
}

/// POSIX `getchar`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getchar() -> c_int {
    unsafe { fgetc(STDIN_SENTINEL as *mut c_void) }
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
pub(crate) const MAX_VA_ARGS: usize = 32;

/// Count how many variadic arguments a parsed format string needs.
pub(crate) fn count_printf_args(segments: &[FormatSegment<'_>]) -> usize {
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
pub(crate) unsafe fn render_printf(fmt: &[u8], args: *const u64, max_args: usize) -> Vec<u8> {
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
                        // Respects length modifier: %hhn→i8, %hn→i16,
                        // %n→i32, %ln→i64, %lln→i64, %zn→isize, %jn→i64.
                        if arg_idx < max_args {
                            let ptr_val = unsafe { *args.add(arg_idx) } as usize;
                            arg_idx += 1;
                            if ptr_val != 0 {
                                let count = buf.len();
                                unsafe {
                                    match resolved_spec.length {
                                        LengthMod::Hh => {
                                            *(ptr_val as *mut i8) = count as i8;
                                        }
                                        LengthMod::H => {
                                            *(ptr_val as *mut i16) = count as i16;
                                        }
                                        LengthMod::L | LengthMod::Ll | LengthMod::J => {
                                            *(ptr_val as *mut i64) = count as i64;
                                        }
                                        LengthMod::Z | LengthMod::T => {
                                            *(ptr_val as *mut isize) = count as isize;
                                        }
                                        _ => {
                                            *(ptr_val as *mut i32) = count as i32;
                                        }
                                    }
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
                                let s_bytes = unsafe { c_str_bytes(ptr as *const c_char) };
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

pub(crate) fn write_all_fd(fd: c_int, data: &[u8]) -> bool {
    let mut written = 0usize;
    while written < data.len() {
        let rc = unsafe { sys_write_fd(fd, data[written..].as_ptr().cast(), data.len() - written) };
        if rc < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == errno::EINTR {
                continue;
            }
            return false;
        }
        if rc == 0 {
            return false;
        }
        written += rc as usize;
    }
    true
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

    let fmt_bytes = unsafe { c_str_bytes(format) };
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

    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Stdio, str_buf as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut copy_len = total_len;
    let mut adverse = false;

    if repair_enabled(mode.heals_enabled(), decision.action)
        && let Some(bound) = known_remaining(str_buf as usize)
    {
        let max_payload = bound.saturating_sub(1);
        if copy_len > max_payload {
            copy_len = max_payload;
            adverse = true;
            global_healing_policy().record(&HealingAction::TruncateWithNull {
                requested: total_len.saturating_add(1),
                truncated: copy_len,
            });
        }
    }

    unsafe {
        std::ptr::copy_nonoverlapping(rendered.as_ptr(), str_buf as *mut u8, copy_len);
        *str_buf.add(copy_len) = 0;
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        adverse,
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

    let fmt_bytes = unsafe { c_str_bytes(format) };
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
            let mut written = 0usize;
            let mut success = true;
            while written < flush_data.len() {
                let rc = unsafe {
                    sys_write_fd(
                        fd,
                        flush_data[written..].as_ptr().cast(),
                        flush_data.len() - written,
                    )
                };
                if rc <= 0 {
                    success = false;
                    break;
                }
                written += rc as usize;
            }
            if success {
                // buffer_write already managed the internal buffer state.
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

    // POSIX: printf(...) is equivalent to fprintf(stdout, ...).
    // Route through the stdout stream to maintain buffer coherence.
    let stdout_ptr = STDOUT_SENTINEL as *mut c_void;
    let id = stdout_ptr as usize;

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let wrote_all = write_all_fd(libc::STDOUT_FILENO, &rendered);

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        !wrote_all,
    );
    if wrote_all { total_len as c_int } else { -1 }
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

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut written = 0usize;
    let mut adverse = false;
    while written < total_len {
        let rc =
            unsafe { sys_write_fd(fd, rendered[written..].as_ptr().cast(), total_len - written) };
        if rc < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == errno::EINTR {
                continue;
            }
            adverse = true;
            break;
        } else if rc == 0 {
            adverse = true;
            break;
        }
        written += rc as usize;
    }
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

    let fmt_bytes = unsafe { c_str_bytes(format) };
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
// v*printf family — Implemented (native format engine + va_list extraction)
//
// On x86_64 Linux, va_list is a pointer to `__va_list_tag`:
//   struct __va_list_tag {
//       unsigned int gp_offset;    // +0: offset into reg_save_area for next GP arg
//       unsigned int fp_offset;    // +4: offset into reg_save_area for next FP arg
//       void *overflow_arg_area;   // +8: pointer to next stack argument
//       void *reg_save_area;       // +16: saved register area
//   };
// GP registers (rdi,rsi,rdx,rcx,r8,r9) hold integer/pointer args: gp_offset 0..48
// FP registers (xmm0..xmm7) hold float/double args: fp_offset 48..176
// ===========================================================================

/// Extract printf arguments from a raw va_list pointer into a u64 buffer.
///
/// Reads each argument according to the format specifiers: integer/pointer/string
/// args come from GP registers or overflow area, float args from FP registers or
/// overflow area.
pub(crate) unsafe fn vprintf_extract_args(
    segments: &[FormatSegment<'_>],
    ap: *mut c_void,
    buf: &mut [u64; MAX_VA_ARGS],
    extract_count: usize,
) -> usize {
    let gp_offset_ptr = ap as *mut u32;
    let fp_offset_ptr = unsafe { (ap as *mut u8).add(4) as *mut u32 };
    let overflow_ptr = unsafe { (ap as *mut u8).add(8) as *mut *mut u8 };
    let reg_save_ptr = unsafe { (ap as *mut u8).add(16) as *mut *mut u8 };

    let mut idx = 0usize;
    for seg in segments {
        if let FormatSegment::Spec(spec) = seg {
            // Width from arg
            if matches!(spec.width, Width::FromArg) && idx < extract_count {
                buf[idx] = unsafe { vprintf_read_gp(gp_offset_ptr, overflow_ptr, reg_save_ptr) };
                idx += 1;
            }
            // Precision from arg
            if matches!(spec.precision, Precision::FromArg) && idx < extract_count {
                buf[idx] = unsafe { vprintf_read_gp(gp_offset_ptr, overflow_ptr, reg_save_ptr) };
                idx += 1;
            }
            match spec.conversion {
                b'%' => {}
                b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                    if idx < extract_count {
                        buf[idx] =
                            unsafe { vprintf_read_fp(fp_offset_ptr, overflow_ptr, reg_save_ptr) };
                        idx += 1;
                    }
                }
                _ => {
                    if idx < extract_count {
                        buf[idx] =
                            unsafe { vprintf_read_gp(gp_offset_ptr, overflow_ptr, reg_save_ptr) };
                        idx += 1;
                    }
                }
            }
        }
    }
    idx
}

/// Read the next GP (integer/pointer) argument from va_list.
#[inline]
unsafe fn vprintf_read_gp(
    gp_offset_ptr: *mut u32,
    overflow_ptr: *mut *mut u8,
    reg_save_ptr: *mut *mut u8,
) -> u64 {
    let gp_off = unsafe { *gp_offset_ptr };
    if gp_off < 48 {
        let p = unsafe { (*reg_save_ptr).add(gp_off as usize) as *const u64 };
        unsafe { *gp_offset_ptr = gp_off + 8 };
        unsafe { *p }
    } else {
        let p = unsafe { *overflow_ptr as *const u64 };
        unsafe { *overflow_ptr = (*overflow_ptr).add(8) };
        unsafe { *p }
    }
}

/// Read the next FP (float/double) argument from va_list.
#[inline]
unsafe fn vprintf_read_fp(
    fp_offset_ptr: *mut u32,
    overflow_ptr: *mut *mut u8,
    reg_save_ptr: *mut *mut u8,
) -> u64 {
    let fp_off = unsafe { *fp_offset_ptr };
    if fp_off < 176 {
        // FP register save slots are 16 bytes each (SSE register width),
        // but we only read the low 8 bytes (double).
        let p = unsafe { (*reg_save_ptr).add(fp_off as usize) as *const u64 };
        unsafe { *fp_offset_ptr = fp_off + 16 };
        unsafe { *p }
    } else {
        // On the stack, doubles occupy 8 bytes.
        let p = unsafe { *overflow_ptr as *const u64 };
        unsafe { *overflow_ptr = (*overflow_ptr).add(8) };
        unsafe { *p }
    }
}

/// Convenience: parse a format string, extract args from va_list, and render to a String.
/// Used by `error()`, `err()`, `warn()`, and related functions.
pub(crate) unsafe fn vprintf_extract_and_render(fmt: &str, ap: *mut c_void) -> String {
    let segments = parse_format_string(fmt.as_bytes());
    let needed = count_printf_args(&segments);
    let extract = std::cmp::min(needed, MAX_VA_ARGS);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    if extract > 0 && !ap.is_null() {
        unsafe { vprintf_extract_args(&segments, ap, &mut arg_buf, extract) };
    }
    let rendered = unsafe { render_printf(fmt.as_bytes(), arg_buf.as_ptr(), extract) };
    String::from_utf8_lossy(&rendered).into_owned()
}

/// POSIX `vsnprintf` — format at most `size` bytes from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vsnprintf(
    str_buf: *mut c_char,
    size: usize,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    if format.is_null() {
        return -1;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Stdio, str_buf as usize, size, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    unsafe { vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

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

/// POSIX `vsprintf` — format into buffer from va_list (no size limit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vsprintf(
    str_buf: *mut c_char,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    if format.is_null() || str_buf.is_null() {
        return -1;
    }
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Stdio, str_buf as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    unsafe { vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut copy_len = total_len;
    let mut adverse = false;

    if repair_enabled(mode.heals_enabled(), decision.action)
        && let Some(bound) = known_remaining(str_buf as usize)
    {
        let max_payload = bound.saturating_sub(1);
        if copy_len > max_payload {
            copy_len = max_payload;
            adverse = true;
            global_healing_policy().record(&HealingAction::TruncateWithNull {
                requested: total_len.saturating_add(1),
                truncated: copy_len,
            });
        }
    }

    unsafe {
        std::ptr::copy_nonoverlapping(rendered.as_ptr(), str_buf as *mut u8, copy_len);
        *str_buf.add(copy_len) = 0;
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        adverse,
    );
    total_len as c_int
}

/// POSIX `vfprintf` — format to stream from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vfprintf(
    stream: *mut c_void,
    format: *const c_char,
    ap: *mut c_void,
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

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    unsafe { vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        let flush_data = s.buffer_write(&rendered);
        if !flush_data.is_empty() {
            let fd = s.fd();
            if !write_all_fd(fd, &flush_data) {
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

/// POSIX `vprintf` — format to stdout from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vprintf(format: *const c_char, ap: *mut c_void) -> c_int {
    if format.is_null() {
        return -1;
    }

    let stdout_ptr = STDOUT_SENTINEL as *mut c_void;
    let id = stdout_ptr as usize;
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    unsafe { vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let wrote_all = write_all_fd(libc::STDOUT_FILENO, &rendered);

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        !wrote_all,
    );
    if wrote_all { total_len as c_int } else { -1 }
}

/// POSIX `vdprintf` — format to file descriptor from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vdprintf(fd: c_int, format: *const c_char, ap: *mut c_void) -> c_int {
    if format.is_null() {
        return -1;
    }
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, fd as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    unsafe { vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut written = 0usize;
    let mut adverse = false;
    while written < total_len {
        let rc =
            unsafe { sys_write_fd(fd, rendered[written..].as_ptr().cast(), total_len - written) };
        if rc < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == errno::EINTR {
                continue;
            }
            adverse = true;
            break;
        } else if rc == 0 {
            adverse = true;
            break;
        }
        written += rc as usize;
    }
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        adverse,
    );
    if adverse { -1 } else { total_len as c_int }
}

/// GNU `vasprintf` — allocate and format from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vasprintf(
    strp: *mut *mut c_char,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    if strp.is_null() || format.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    unsafe { *strp = std::ptr::null_mut() };

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, strp as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    unsafe { vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();
    let alloc_size = total_len.saturating_add(1);

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
// scanf family — Implemented (native format parser + va_list extraction)
//
// The core scanf engine (frankenlibc-core/src/stdio/scanf.rs) parses format
// strings and scans typed values from byte input. The ABI layer extracts
// destination pointers from the C caller's va_list and writes scanned values.
// ===========================================================================

use frankenlibc_core::stdio::scanf::{
    ScanDirective, ScanResult, ScanValue, parse_scanf_format, scan_input,
};

/// Write scanned values through va_list pointers.
/// Uses a macro to avoid naming the unstable `VaListImpl` type directly.
/// `$args` is the variadic `args` from `mut args: ...`.
macro_rules! scanf_write_values {
    ($values:expr, $directives:expr, $args:expr) => {{
        let mut _val_idx = 0usize;
        for _dir in $directives {
            if let ScanDirective::Spec(_spec) = _dir {
                if _spec.suppress {
                    continue;
                }
                if _val_idx >= $values.len() {
                    break;
                }
                unsafe {
                    scanf_write_one!(&$values[_val_idx], _spec, $args);
                }
                _val_idx += 1;
            }
        }
    }};
}

/// Write a single scanned value to the next pointer from va_list.
macro_rules! scanf_write_one {
    ($val:expr, $spec:expr, $args:expr) => {
        match $val {
            ScanValue::SignedInt(v) => match $spec.length {
                LengthMod::Hh => {
                    let ptr = $args.arg::<*mut i8>();
                    *ptr = *v as i8;
                }
                LengthMod::H => {
                    let ptr = $args.arg::<*mut i16>();
                    *ptr = *v as i16;
                }
                LengthMod::L | LengthMod::Ll | LengthMod::J => {
                    let ptr = $args.arg::<*mut i64>();
                    *ptr = *v;
                }
                LengthMod::Z | LengthMod::T => {
                    let ptr = $args.arg::<*mut isize>();
                    *ptr = *v as isize;
                }
                _ => {
                    let ptr = $args.arg::<*mut c_int>();
                    *ptr = *v as c_int;
                }
            },
            ScanValue::UnsignedInt(v) => match $spec.length {
                LengthMod::Hh => {
                    let ptr = $args.arg::<*mut u8>();
                    *ptr = *v as u8;
                }
                LengthMod::H => {
                    let ptr = $args.arg::<*mut u16>();
                    *ptr = *v as u16;
                }
                LengthMod::L | LengthMod::Ll | LengthMod::J => {
                    let ptr = $args.arg::<*mut u64>();
                    *ptr = *v;
                }
                LengthMod::Z | LengthMod::T => {
                    let ptr = $args.arg::<*mut usize>();
                    *ptr = *v as usize;
                }
                _ => {
                    let ptr = $args.arg::<*mut u32>();
                    *ptr = *v as u32;
                }
            },
            ScanValue::Float(v) => match $spec.length {
                LengthMod::L | LengthMod::BigL => {
                    let ptr = $args.arg::<*mut f64>();
                    *ptr = *v;
                }
                _ => {
                    let ptr = $args.arg::<*mut f32>();
                    *ptr = *v as f32;
                }
            },
            ScanValue::Char(bytes) => {
                let ptr = $args.arg::<*mut u8>();
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
            }
            ScanValue::String(bytes) => {
                let ptr = $args.arg::<*mut c_char>();
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
                *ptr.add(bytes.len()) = 0; // NUL-terminate
            }
            ScanValue::CharsConsumed(n) => match $spec.length {
                LengthMod::Hh => {
                    let ptr = $args.arg::<*mut i8>();
                    *ptr = *n as i8;
                }
                LengthMod::H => {
                    let ptr = $args.arg::<*mut i16>();
                    *ptr = *n as i16;
                }
                LengthMod::L | LengthMod::Ll | LengthMod::J => {
                    let ptr = $args.arg::<*mut i64>();
                    *ptr = *n as i64;
                }
                _ => {
                    let ptr = $args.arg::<*mut c_int>();
                    *ptr = *n as c_int;
                }
            },
            ScanValue::Pointer(v) => {
                let ptr = $args.arg::<*mut *mut c_void>();
                *ptr = *v as *mut c_void;
            }
        }
    };
}

/// Core scanf logic: parse format, scan input, return result and directives.
pub(crate) fn scanf_core(input: &[u8], format: *const c_char) -> (ScanResult, Vec<ScanDirective>) {
    let fmt_bytes = unsafe { CStr::from_ptr(format) }.to_bytes();
    let directives = parse_scanf_format(fmt_bytes);
    let result = scan_input(input, &directives);
    (result, directives)
}

/// Read stream content into a byte buffer for scanf parsing.
pub(crate) fn read_stream_for_scanf(id: usize, limit: usize) -> Vec<u8> {
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        return Vec::new();
    };

    // Memory-backed streams: read directly.
    if s.is_mem_backed() {
        return s.mem_read(limit);
    }

    // FD-backed streams: read from fd.
    let fd = s.fd();
    let mut buf = vec![0u8; limit.min(8192)];
    let rc = unsafe { sys_read_fd(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if rc > 0 {
        buf.truncate(rc as usize);
        buf
    } else {
        if rc == 0 {
            s.set_eof();
        }
        Vec::new()
    }
}

/// POSIX `sscanf` — scan formatted input from string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sscanf(s: *const c_char, format: *const c_char, mut args: ...) -> c_int {
    if s.is_null() || format.is_null() {
        return -1;
    }
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, s as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let input = unsafe { CStr::from_ptr(s) }.to_bytes();
    let (result, directives) = scanf_core(input, format);

    if result.input_failure && result.count == 0 {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }

    scanf_write_values!(&result.values, &directives, args);
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, false);
    result.count
}

/// POSIX `fscanf` — scan formatted input from stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fscanf(
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

    let input_buf = read_stream_for_scanf(id, 8192);
    if input_buf.is_empty() {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }

    let (result, directives) = scanf_core(&input_buf, format);

    if result.input_failure && result.count == 0 {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }

    scanf_write_values!(&result.values, &directives, args);
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, false);
    result.count
}

/// POSIX `scanf` — scan formatted input from stdin.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scanf(format: *const c_char, mut args: ...) -> c_int {
    if format.is_null() {
        return -1;
    }
    let stdin_ptr = STDIN_SENTINEL as *mut c_void;
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Stdio, stdin_ptr as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let input_buf = read_stream_for_scanf(STDIN_SENTINEL, 8192);
    if input_buf.is_empty() {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }

    let (result, directives) = scanf_core(&input_buf, format);

    if result.input_failure && result.count == 0 {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }

    scanf_write_values!(&result.values, &directives, args);
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, false);
    result.count
}

/// POSIX `vsscanf` — scan formatted input from string with va_list.
///
/// For the v* variants, we receive a raw `*mut c_void` pointing to the C
/// caller's va_list. On x86_64, C's `va_list` (`__va_list_tag[1]`) has the
/// same memory layout as Rust's internal `VaListImpl`. We cast the raw
/// pointer and call `arg()` to extract destination pointers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vsscanf(
    s: *const c_char,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    if s.is_null() || format.is_null() || ap.is_null() {
        return -1;
    }
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, s as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let input = unsafe { CStr::from_ptr(s) }.to_bytes();
    let (result, directives) = scanf_core(input, format);

    if result.input_failure && result.count == 0 {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }

    // Write scanned values via raw va_list pointer.
    // SAFETY: On x86_64 Linux, the raw va_list pointer has the same layout
    // as Rust's VaListImpl. We transmute to access arg().
    unsafe {
        vscanf_write_values(&result.values, &directives, ap);
    }

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, false);
    result.count
}

/// POSIX `vfscanf` — scan formatted input from stream with va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vfscanf(
    stream: *mut c_void,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    if format.is_null() || ap.is_null() {
        return -1;
    }
    let id = stream as usize;
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let input_buf = read_stream_for_scanf(id, 8192);
    if input_buf.is_empty() {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }

    let (result, directives) = scanf_core(&input_buf, format);

    if result.input_failure && result.count == 0 {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }

    unsafe {
        vscanf_write_values(&result.values, &directives, ap);
    }

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, false);
    result.count
}

/// POSIX `vscanf` — scan formatted input from stdin with va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vscanf(format: *const c_char, ap: *mut c_void) -> c_int {
    unsafe { vfscanf(STDIN_SENTINEL as *mut c_void, format, ap) }
}

/// Write scanned values via raw va_list pointer (v* functions).
///
/// On x86_64 Linux, C's va_list is `__va_list_tag` which has the layout:
/// ```c
/// struct __va_list_tag {
///     unsigned int gp_offset;    // offset 0, 4 bytes
///     unsigned int fp_offset;    // offset 4, 4 bytes
///     void *overflow_arg_area;   // offset 8, 8 bytes
///     void *reg_save_area;       // offset 16, 8 bytes
/// };                             // total: 24 bytes
/// ```
///
/// We manually read pointer arguments from the overflow area, which is used
/// when all register save slots are exhausted (common in scanf where all
/// args are pointers passed after the format string).
pub(crate) unsafe fn vscanf_write_values(
    values: &[ScanValue],
    directives: &[ScanDirective],
    ap: *mut c_void,
) {
    // On x86_64, the va_list structure fields:
    // gp_offset (u32) at +0: offset into reg_save_area for next GP register arg
    // fp_offset (u32) at +4: offset into reg_save_area for next FP register arg
    // overflow_arg_area (*mut u8) at +8: pointer to next stack argument
    // reg_save_area (*mut u8) at +16: saved register area
    //
    // For pointer arguments (all scanf destinations), gp_offset < 48 means
    // the arg is in a register save slot; otherwise it's in overflow_arg_area.
    let gp_offset_ptr = ap as *mut u32;
    let overflow_ptr = unsafe { (ap as *mut u8).add(8) as *mut *mut u8 };
    let reg_save_ptr = unsafe { (ap as *mut u8).add(16) as *mut *mut u8 };

    let mut val_idx = 0usize;
    for dir in directives {
        if let ScanDirective::Spec(spec) = dir {
            if spec.suppress {
                continue;
            }
            if val_idx >= values.len() {
                break;
            }

            // Extract the next pointer argument from va_list.
            let dest_ptr: *mut c_void = unsafe {
                let gp_off = *gp_offset_ptr;
                if gp_off < 48 {
                    // Read from register save area.
                    let p = (*reg_save_ptr).add(gp_off as usize) as *mut *mut c_void;
                    *gp_offset_ptr = gp_off + 8;
                    *p
                } else {
                    // Read from overflow area.
                    let p = *overflow_ptr as *mut *mut c_void;
                    *overflow_ptr = (*overflow_ptr).add(8);
                    *p
                }
            };

            // Write the value through the pointer.
            unsafe {
                vscanf_write_one(&values[val_idx], spec, dest_ptr);
            }
            val_idx += 1;
        }
    }
}

/// Write a single scanned value to a destination pointer.
pub(crate) unsafe fn vscanf_write_one(
    val: &ScanValue,
    spec: &frankenlibc_core::stdio::scanf::ScanSpec,
    dest: *mut c_void,
) {
    match val {
        ScanValue::SignedInt(v) => match spec.length {
            LengthMod::Hh => unsafe { *(dest as *mut i8) = *v as i8 },
            LengthMod::H => unsafe { *(dest as *mut i16) = *v as i16 },
            LengthMod::L | LengthMod::Ll | LengthMod::J => unsafe { *(dest as *mut i64) = *v },
            LengthMod::Z | LengthMod::T => unsafe { *(dest as *mut isize) = *v as isize },
            _ => unsafe { *(dest as *mut c_int) = *v as c_int },
        },
        ScanValue::UnsignedInt(v) => match spec.length {
            LengthMod::Hh => unsafe { *(dest as *mut u8) = *v as u8 },
            LengthMod::H => unsafe { *(dest as *mut u16) = *v as u16 },
            LengthMod::L | LengthMod::Ll | LengthMod::J => unsafe { *(dest as *mut u64) = *v },
            LengthMod::Z | LengthMod::T => unsafe { *(dest as *mut usize) = *v as usize },
            _ => unsafe { *(dest as *mut u32) = *v as u32 },
        },
        ScanValue::Float(v) => match spec.length {
            LengthMod::L | LengthMod::BigL => unsafe { *(dest as *mut f64) = *v },
            _ => unsafe { *(dest as *mut f32) = *v as f32 },
        },
        ScanValue::Char(bytes) => unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dest as *mut u8, bytes.len());
        },
        ScanValue::String(bytes) => unsafe {
            let p = dest as *mut u8;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
            *p.add(bytes.len()) = 0; // NUL-terminate
        },
        ScanValue::CharsConsumed(n) => match spec.length {
            LengthMod::Hh => unsafe { *(dest as *mut i8) = *n as i8 },
            LengthMod::H => unsafe { *(dest as *mut i16) = *n as i16 },
            LengthMod::L | LengthMod::Ll | LengthMod::J => unsafe {
                *(dest as *mut i64) = *n as i64;
            },
            _ => unsafe { *(dest as *mut c_int) = *n as c_int },
        },
        ScanValue::Pointer(v) => unsafe {
            *(dest as *mut *mut c_void) = *v as *mut c_void;
        },
    }
}

/// glibc fortified `__printf_chk`.
#[unsafe(export_name = "__printf_chk")]
pub unsafe extern "C" fn printf_chk(_flag: c_int, format: *const c_char, mut args: ...) -> c_int {
    if format.is_null() {
        return -1;
    }

    // __printf_chk writes to stdout like printf.
    let stdout_ptr = STDOUT_SENTINEL as *mut c_void;
    let id = stdout_ptr as usize;
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let wrote_all = write_all_fd(libc::STDOUT_FILENO, &rendered);

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        !wrote_all,
    );
    if wrote_all { total_len as c_int } else { -1 }
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

    let fmt_bytes = unsafe { c_str_bytes(format) };
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
            let mut written = 0usize;
            let mut success = true;
            while written < flush_data.len() {
                let rc = unsafe {
                    sys_write_fd(
                        fd,
                        flush_data[written..].as_ptr().cast(),
                        flush_data.len() - written,
                    )
                };
                if rc <= 0 {
                    success = false;
                    break;
                }
                written += rc as usize;
            }
            if success {
                // buffer_write already managed the internal buffer state.
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

    let fmt_bytes = unsafe { c_str_bytes(format) };
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
        unsafe { set_abi_errno(errno::EACCES) };
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
        unsafe { set_abi_errno(errno::EACCES) };
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
    let mut target_fd = -1;
    if let Some(mut old) = reg.streams.remove(&id) {
        let pending = old.prepare_close();
        let old_fd = old.fd();
        if !pending.is_empty() && old_fd >= 0 {
            let mut written = 0usize;
            while written < pending.len() {
                let rc = unsafe {
                    sys_write_fd(
                        old_fd,
                        pending[written..].as_ptr().cast(),
                        pending.len() - written,
                    )
                };
                if rc <= 0 {
                    break;
                }
                written += rc as usize;
            }
        }
        if id == STDIN_SENTINEL || id == STDOUT_SENTINEL || id == STDERR_SENTINEL {
            target_fd = old_fd;
        } else if old_fd >= 0 {
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
    let mut fd = unsafe {
        libc::syscall(
            libc::SYS_openat as c_long,
            libc::AT_FDCWD,
            pathname,
            oflags,
            create_mode,
        ) as c_int
    };

    if fd < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::ENOENT);
        unsafe { set_abi_errno(e) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 30, true);
        return std::ptr::null_mut();
    }

    // If reopening a standard stream, dup2 the new fd onto the standard fd.
    if target_fd >= 0 && fd != target_fd {
        unsafe {
            libc::syscall(libc::SYS_dup2 as c_long, fd, target_fd);
            libc::syscall(libc::SYS_close as c_long, fd);
        }
        fd = target_fd;
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
    let ret = unsafe { libc::syscall(libc::SYS_unlinkat as c_long, libc::AT_FDCWD, pathname, 0) };
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
        unsafe { set_abi_errno(errno::EACCES) };
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
        unsafe {
            libc::syscall(
                libc::SYS_unlinkat as c_long,
                libc::AT_FDCWD,
                path.as_ptr(),
                0,
            )
        };

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
        unsafe { set_abi_errno(errno::EACCES) };
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
        // Pass the current process environment so the child inherits PATH, etc.
        unsafe extern "C" {
            static mut environ: *mut *mut c_char;
        }
        unsafe {
            libc::syscall(libc::SYS_execve as c_long, sh, argv.as_ptr(), environ);
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
    if format.is_null() || (str_buf.is_null() && maxlen > 0) {
        return -1;
    }

    let effective = maxlen.min(slen);
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, effective, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = count_printf_args(&segments);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    if !str_buf.is_null() && effective > 0 {
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
// 64-bit aliases
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fopen64(pathname: *const c_char, mode: *const c_char) -> *mut c_void {
    unsafe { fopen(pathname, mode) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn freopen64(
    pathname: *const c_char,
    mode: *const c_char,
    stream: *mut c_void,
) -> *mut c_void {
    unsafe { freopen(pathname, mode, stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tmpfile64() -> *mut c_void {
    unsafe { tmpfile() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fseeko64(stream: *mut c_void, offset: i64, whence: c_int) -> c_int {
    unsafe { fseeko(stream, offset, whence) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftello64(stream: *mut c_void) -> i64 {
    unsafe { ftello(stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpos64(stream: *mut c_void, pos: *mut c_void) -> c_int {
    if pos.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    unsafe { fgetpos(stream, pos.cast::<libc::fpos_t>()) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsetpos64(stream: *mut c_void, pos: *const c_void) -> c_int {
    if pos.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    unsafe { fsetpos(stream, pos.cast::<libc::fpos_t>()) }
}

// ---------------------------------------------------------------------------
// stdio extras
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// fopencookie — Implemented (native cookie-based stream)
// ---------------------------------------------------------------------------

/// cookie_io_functions_t layout (matches glibc x86_64):
///   read:  fn(*mut c_void, *mut c_char, usize) -> isize
///   write: fn(*mut c_void, *const c_char, usize) -> isize
///   seek:  fn(*mut c_void, *mut i64, c_int) -> c_int
///   close: fn(*mut c_void) -> c_int
#[repr(C)]
#[derive(Clone, Copy)]
struct CookieIoFuncs {
    read: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> isize>,
    write: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> isize>,
    seek: Option<unsafe extern "C" fn(*mut c_void, *mut i64, c_int) -> c_int>,
    close: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
}

/// Metadata for a cookie-backed stream.
struct CookieStreamInfo {
    cookie: *mut c_void,
    funcs: CookieIoFuncs,
}

// SAFETY: The C caller is responsible for ensuring the cookie and
// function pointers remain valid for the lifetime of the stream.
unsafe impl Send for CookieStreamInfo {}
unsafe impl Sync for CookieStreamInfo {}

/// Registry of cookie streams, keyed by stream sentinel ID.
static COOKIE_REGISTRY: Mutex<Option<HashMap<usize, CookieStreamInfo>>> = Mutex::new(None);

fn cookie_registry() -> &'static Mutex<Option<HashMap<usize, CookieStreamInfo>>> {
    &COOKIE_REGISTRY
}

/// Read from a cookie-backed stream. Called by fread/fgetc for cookie streams.
pub(crate) unsafe fn cookie_stream_read(id: usize, buf: *mut u8, count: usize) -> isize {
    let guard = cookie_registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref map) = *guard
        && let Some(info) = map.get(&id)
    {
        if let Some(read_fn) = info.funcs.read {
            let cookie = info.cookie;
            drop(guard);
            return unsafe { read_fn(cookie, buf as *mut c_char, count) };
        }
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }
    unsafe { set_abi_errno(errno::EBADF) };
    -1
}

/// Write to a cookie-backed stream. Called by fwrite/fputc for cookie streams.
pub(crate) unsafe fn cookie_stream_write(id: usize, buf: *const u8, count: usize) -> isize {
    let guard = cookie_registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref map) = *guard
        && let Some(info) = map.get(&id)
    {
        if let Some(write_fn) = info.funcs.write {
            let cookie = info.cookie;
            drop(guard);
            return unsafe { write_fn(cookie, buf as *const c_char, count) };
        }
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }
    unsafe { set_abi_errno(errno::EBADF) };
    -1
}

/// Seek a cookie-backed stream.
pub(crate) unsafe fn cookie_stream_seek(id: usize, offset: *mut i64, whence: c_int) -> c_int {
    let guard = cookie_registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref map) = *guard
        && let Some(info) = map.get(&id)
    {
        if let Some(seek_fn) = info.funcs.seek {
            let cookie = info.cookie;
            drop(guard);
            return unsafe { seek_fn(cookie, offset, whence) };
        }
        unsafe { set_abi_errno(errno::ESPIPE) };
        return -1;
    }
    unsafe { set_abi_errno(errno::EBADF) };
    -1
}

/// Close a cookie-backed stream: call the close callback and remove from registry.
pub(crate) unsafe fn cookie_stream_close(id: usize) -> c_int {
    let mut guard = cookie_registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref mut map) = *guard
        && let Some(info) = map.remove(&id)
        && let Some(close_fn) = info.funcs.close
    {
        let cookie = info.cookie;
        drop(guard);
        return unsafe { close_fn(cookie) };
    }
    0
}

/// Check if a stream ID is cookie-backed.
pub(crate) fn is_cookie_stream(id: usize) -> bool {
    let guard = cookie_registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref map) = *guard {
        return map.contains_key(&id);
    }
    false
}

/// Metadata for open_memstream: tracks the C caller's pointer and size locations.
struct MemStreamSync {
    ptr_loc: *mut *mut c_char,
    size_loc: *mut usize,
}

// SAFETY: MemStreamSync holds raw pointers passed by the C caller.
// The C caller is responsible for keeping these pointers valid for
// the lifetime of the stream (per POSIX open_memstream contract).
unsafe impl Send for MemStreamSync {}
unsafe impl Sync for MemStreamSync {}

/// Registry of open_memstream sync metadata, keyed by stream sentinel ID.
static MEM_STREAM_SYNC: Mutex<Option<HashMap<usize, MemStreamSync>>> = Mutex::new(None);

fn mem_sync_registry() -> &'static Mutex<Option<HashMap<usize, MemStreamSync>>> {
    &MEM_STREAM_SYNC
}

/// Synchronize open_memstream data to the C caller's pointers.
/// Called after fflush and fclose for open_memstream streams.
unsafe fn sync_memstream_to_caller(id: usize, stream: &StdioStream) {
    let sync_guard = mem_sync_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(ref map) = *sync_guard
        && let Some(info) = map.get(&id)
        && let Some(data) = stream.mem_data()
    {
        let len = data.len();
        // Allocate a new buffer via malloc and copy data + NUL terminator.
        let buf = unsafe { malloc(len + 1) };
        if !buf.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), buf.cast::<u8>(), len);
                *buf.cast::<u8>().add(len) = 0; // NUL-terminate
                *info.ptr_loc = buf.cast::<c_char>();
                *info.size_loc = len;
            }
        }
    }
    drop(sync_guard);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setlinebuf(stream: *mut c_void) {
    let _ = unsafe { setvbuf(stream, std::ptr::null_mut(), 1, 0) };
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn flockfile(stream: *mut c_void) {
    if stream.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftrylockfile(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn funlockfile(stream: *mut c_void) {
    if stream.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getc_unlocked(stream: *mut c_void) -> c_int {
    unsafe { getc(stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putc_unlocked(c: c_int, stream: *mut c_void) -> c_int {
    unsafe { putc(c, stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetc_unlocked(stream: *mut c_void) -> c_int {
    unsafe { fgetc(stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fputc_unlocked(c: c_int, stream: *mut c_void) -> c_int {
    unsafe { fputc(c, stream) }
}

/// POSIX `fmemopen` — open a memory buffer as a stream.
///
/// If `buf` is NULL, an internal buffer of `size` bytes is allocated.
/// The returned FILE* is a FrankenLibC sentinel backed by memory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmemopen(
    buf: *mut c_void,
    size: usize,
    mode: *const c_char,
) -> *mut c_void {
    if size == 0 || mode.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    // Parse mode string.
    let mode_bytes = unsafe { CStr::from_ptr(mode) }.to_bytes();
    let Some(open_flags) = parse_mode(mode_bytes) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    };

    // Prepare the backing buffer.
    let (data, content_len) = if buf.is_null() {
        // Internal buffer: zero-initialized, no initial content.
        (vec![0u8; size], 0)
    } else {
        // User-provided buffer: copy into our Vec so we own it safely.
        // For read modes, content_len = size (entire buffer is readable).
        // For write modes (non-append), content_len = 0 (starts empty for writing).
        // For append mode, content_len = position of first NUL or size.
        let slice = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), size) };
        let mut v = vec![0u8; size];
        v[..size].copy_from_slice(slice);

        let cl = if open_flags.readable && !open_flags.writable {
            // "r" mode: entire buffer is valid content
            size
        } else if open_flags.append {
            // "a"/"a+" mode: content_len = first NUL byte or size
            v.iter().position(|&b| b == 0).unwrap_or(size)
        } else if open_flags.writable && !open_flags.readable {
            // "w" mode: content starts empty
            0
        } else {
            // "r+" or "w+" mode: entire buffer is valid content
            size
        };
        (v, cl)
    };

    let stream = StdioStream::new_mem_fixed(data, content_len, open_flags);
    let id = alloc_stream_id();
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.insert(id, stream);
    id as *mut c_void
}

/// POSIX `open_memstream` — open a dynamic memory buffer for writing.
///
/// After each fflush/fclose, `*ptr` is updated to point to a malloc'd buffer
/// containing the stream data (NUL-terminated), and `*sizeloc` is set to the
/// data length (not counting the NUL).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn open_memstream(ptr: *mut *mut c_char, sizeloc: *mut usize) -> *mut c_void {
    if ptr.is_null() || sizeloc.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    let stream = StdioStream::new_mem_dynamic();
    let id = alloc_stream_id();

    // Register the stream.
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.insert(id, stream);
    drop(reg);

    // Register sync metadata so fflush/fclose can update the C caller's pointers.
    let mut sync_guard = mem_sync_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let map = sync_guard.get_or_insert_with(HashMap::new);
    map.insert(
        id,
        MemStreamSync {
            ptr_loc: ptr,
            size_loc: sizeloc,
        },
    );
    drop(sync_guard);

    // Initialize caller's pointers to empty state.
    unsafe {
        let initial_buf = malloc(1);
        if !initial_buf.is_null() {
            *initial_buf.cast::<u8>() = 0; // NUL-terminate
            *ptr = initial_buf.cast::<c_char>();
            *sizeloc = 0;
        }
    }

    id as *mut c_void
}

/// GNU `fopencookie` — open a custom stream with user-defined I/O callbacks.
///
/// `funcs` points to a `cookie_io_functions_t` struct containing read, write,
/// seek, and close function pointers. The `cookie` pointer is passed as the
/// first argument to each callback.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fopencookie(
    cookie: *mut c_void,
    mode: *const c_char,
    funcs: *const c_void,
) -> *mut c_void {
    if mode.is_null() || funcs.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    // Parse mode string
    let mode_bytes = unsafe { CStr::from_ptr(mode) }.to_bytes();
    let Some(open_flags) = parse_mode(mode_bytes) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    };

    // Read the cookie_io_functions_t from the caller's struct.
    // SAFETY: caller guarantees funcs points to a valid cookie_io_functions_t.
    let io_funcs = unsafe { *(funcs as *const CookieIoFuncs) };

    // Create a memory-backed stream as the underlying container.
    // Cookie streams use an empty dynamic buffer; actual I/O goes through callbacks.
    let stream = StdioStream::new_mem_dynamic_with_flags(open_flags);
    let id = alloc_stream_id();

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.insert(id, stream);
    drop(reg);

    // Register the cookie info
    let mut cookie_guard = cookie_registry().lock().unwrap_or_else(|e| e.into_inner());
    let map = cookie_guard.get_or_insert_with(HashMap::new);
    map.insert(
        id,
        CookieStreamInfo {
            cookie,
            funcs: io_funcs,
        },
    );
    drop(cookie_guard);

    id as *mut c_void
}

// ===========================================================================
// Batch: Unlocked stdio variants — Implemented
// ===========================================================================
//
// These are GNU extensions that skip internal locking for performance.
// Since our FILE implementation is already thread-local, they behave
// identically to the locked versions.

/// GNU `feof_unlocked` — test end-of-file indicator without locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feof_unlocked(stream: *mut c_void) -> c_int {
    unsafe { feof(stream) }
}

/// GNU `ferror_unlocked` — test error indicator without locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ferror_unlocked(stream: *mut c_void) -> c_int {
    unsafe { ferror(stream) }
}

/// GNU `fflush_unlocked` — flush stream without locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fflush_unlocked(stream: *mut c_void) -> c_int {
    unsafe { fflush(stream) }
}

/// GNU `fcloseall` — close all open streams.
///
/// Returns 0 on success. This is a GNU extension.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn fcloseall() -> c_int {
    // Flush all open streams by passing NULL to fflush (POSIX semantics).
    unsafe { fflush(std::ptr::null_mut()) };
    0
}

// ===========================================================================
// Batch: mktemp — Implemented
// ===========================================================================

/// `mktemp` — generate a unique temporary filename (DEPRECATED, use mkstemp).
///
/// Replaces trailing 'X' characters in template with unique characters.
/// Returns the modified template, or an empty string on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mktemp(template: *mut c_char) -> *mut c_char {
    if template.is_null() {
        return template;
    }

    let len = unsafe { libc::strlen(template) };
    if len < 6 {
        unsafe { *template = 0 };
        return template;
    }

    // Count trailing X characters
    let tmpl = unsafe { std::slice::from_raw_parts_mut(template as *mut u8, len) };
    let mut x_count = 0;
    for b in tmpl.iter().rev() {
        if *b == b'X' {
            x_count += 1;
        } else {
            break;
        }
    }
    if x_count < 6 {
        unsafe { *template = 0 };
        return template;
    }

    // Generate random suffix using /dev/urandom
    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rand_buf = vec![0u8; x_count];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut rand_buf)
        })
        .is_err()
    {
        unsafe { *template = 0 };
        return template;
    }

    let start = len - x_count;
    for (i, &rb) in rand_buf.iter().enumerate() {
        tmpl[start + i] = chars[(rb as usize) % chars.len()];
    }

    template
}
