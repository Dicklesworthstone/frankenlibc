//! ABI layer for `<stdio.h>` functions.
//!
//! Provides the full POSIX stdio surface: file stream management (fopen/fclose),
//! buffered I/O (fread/fwrite/fgetc/fputc/fgets/fputs), seeking (fseek/ftell/rewind),
//! status (feof/ferror/clearerr), buffering control (setvbuf/setbuf), and
//! character output (putchar/puts/getchar). The printf family is handled via
//! the core printf formatting engine with manual va_list extraction.
//!
//! Architecture: A global stream registry maps opaque `FILE*` addresses to
//! `StdioStream` instances from glibc-rs-core. stdin/stdout/stderr are
//! pre-registered at well-known sentinel addresses.

use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::os::raw::c_long;
use std::sync::{Mutex, OnceLock};

use glibc_rs_core::errno;
use glibc_rs_core::stdio::{BufMode, OpenFlags, StdioStream, flags_to_oflags, parse_mode};
use glibc_rs_membrane::heal::{HealingAction, global_healing_policy};
use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::malloc_abi::known_remaining;
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
            let len = unsafe { CStr::from_ptr(ptr) }.to_bytes().len();
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
#[unsafe(no_mangle)]
pub static stdin: usize = STDIN_SENTINEL;

/// Global `stdout` pointer.
#[unsafe(no_mangle)]
pub static stdout: usize = STDOUT_SENTINEL;

/// Global `stderr` pointer.
#[unsafe(no_mangle)]
pub static stderr: usize = STDERR_SENTINEL;

// ---------------------------------------------------------------------------
// fopen / fclose
// ---------------------------------------------------------------------------

/// POSIX `fopen`.
#[unsafe(no_mangle)]
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
    let stream = StdioStream::new(fd, open_flags);
    let id = alloc_stream_id();
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.insert(id, stream);

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 30, false);
    id as *mut c_void
}

/// POSIX `fclose`.
#[unsafe(no_mangle)]
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

    // Flush pending writes.
    let pending = s.prepare_close();
    let fd = s.fd();
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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

/// POSIX `rewind`.
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clearerr(stream: *mut c_void) {
    let id = stream as usize;
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        s.clear_err();
    }
}

/// POSIX `ungetc`.
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    if s.is_null() {
        return libc::EOF;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        s as usize,
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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

use glibc_rs_core::stdio::{
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
