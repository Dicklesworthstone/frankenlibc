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

#[cfg(not(debug_assertions))]
use core::arch::global_asm;
use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use frankenlibc_core::errno;
use frankenlibc_core::stdio::{BufMode, OpenFlags, StdioStream, flags_to_oflags, parse_mode};
use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::io_internal_abi::{self, NativeFileBufMode};
use crate::malloc_abi::{free, known_remaining, malloc};
use crate::runtime_policy;
use crate::unistd_abi::{sys_read_fd, sys_write_fd};

type HostFcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type HostFwriteFn = unsafe extern "C" fn(*const c_void, usize, usize, *mut c_void) -> usize;
type HostFputsFn = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;
type HostFputcFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
type HostFilenoFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type HostFeofFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type HostFerrorFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type HostClearerrFn = unsafe extern "C" fn(*mut c_void);
type HostFgetcFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type HostFgetsFn = unsafe extern "C" fn(*mut c_char, c_int, *mut c_void) -> *mut c_char;
type HostFreadFn = unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void) -> usize;
type HostUngetcFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
type HostFseekFn = unsafe extern "C" fn(*mut c_void, c_long, c_int) -> c_int;
type HostFtellFn = unsafe extern "C" fn(*mut c_void) -> c_long;
type HostFflushFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type HostSetvbufFn = unsafe extern "C" fn(*mut c_void, *mut c_char, c_int, usize) -> c_int;
type HostGetdelimFn =
    unsafe extern "C" fn(*mut *mut c_char, *mut usize, c_int, *mut c_void) -> isize;
type HostGetlineFn = unsafe extern "C" fn(*mut *mut c_char, *mut usize, *mut c_void) -> isize;
type HostVfscanfFn = unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void) -> c_int;
type HostFgetposFn = unsafe extern "C" fn(*mut c_void, *mut libc::fpos_t) -> c_int;
type HostFsetposFn = unsafe extern "C" fn(*mut c_void, *const libc::fpos_t) -> c_int;
type HostFreopenFn = unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void) -> *mut c_void;
type HostFlockfileFn = unsafe extern "C" fn(*mut c_void);
type HostFunlockfileFn = unsafe extern "C" fn(*mut c_void);
type HostFtrylockfileFn = unsafe extern "C" fn(*mut c_void) -> c_int;

static HOST_FCLOSE_FN: OnceLock<usize> = OnceLock::new();
static HOST_FWRITE_FN: OnceLock<usize> = OnceLock::new();
static HOST_FPUTS_FN: OnceLock<usize> = OnceLock::new();
static HOST_FPUTC_FN: OnceLock<usize> = OnceLock::new();
static HOST_FILENO_FN: OnceLock<usize> = OnceLock::new();
static HOST_FEOF_FN: OnceLock<usize> = OnceLock::new();
static HOST_FERROR_FN: OnceLock<usize> = OnceLock::new();
static HOST_CLEARERR_FN: OnceLock<usize> = OnceLock::new();
static HOST_FGETC_FN: OnceLock<usize> = OnceLock::new();
static HOST_FGETS_FN: OnceLock<usize> = OnceLock::new();
static HOST_FREAD_FN: OnceLock<usize> = OnceLock::new();
static HOST_UNGETC_FN: OnceLock<usize> = OnceLock::new();
static HOST_FSEEK_FN: OnceLock<usize> = OnceLock::new();
static HOST_FTELL_FN: OnceLock<usize> = OnceLock::new();
static HOST_FFLUSH_FN: OnceLock<usize> = OnceLock::new();
static HOST_SETVBUF_FN: OnceLock<usize> = OnceLock::new();
static HOST_GETDELIM_FN: OnceLock<usize> = OnceLock::new();
static HOST_GETLINE_FN: OnceLock<usize> = OnceLock::new();
static HOST_VFSCANF_FN: OnceLock<usize> = OnceLock::new();
static HOST_FGETPOS_FN: OnceLock<usize> = OnceLock::new();
static HOST_FSETPOS_FN: OnceLock<usize> = OnceLock::new();
static HOST_FREOPEN_FN: OnceLock<usize> = OnceLock::new();
static HOST_FLOCKFILE_FN: OnceLock<usize> = OnceLock::new();
static HOST_FUNLOCKFILE_FN: OnceLock<usize> = OnceLock::new();
static HOST_FTRYLOCKFILE_FN: OnceLock<usize> = OnceLock::new();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn repair_enabled(heals_enabled: bool, action: MembraneAction) -> bool {
    heals_enabled || matches!(action, MembraneAction::Repair(_))
}

#[inline]
fn native_file_buf_mode(mode: BufMode) -> NativeFileBufMode {
    match mode {
        BufMode::Full => NativeFileBufMode::Full,
        BufMode::Line => NativeFileBufMode::Line,
        BufMode::None => NativeFileBufMode::None,
    }
}

unsafe fn scan_c_str_len(ptr: *const c_char, bound: Option<usize>) -> (usize, bool) {
    let limit = bound.or_else(|| known_remaining(ptr as usize));
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

/// Runtime-dispatch state for stream/syscall policy lookups.
/// Seek/Close rows are reserved for upcoming policy-routing of those operations.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamPolicyState {
    Read = 0,
    Write = 1,
    Seek = 2,
    Close = 3,
}

const STREAM_POLICY_STATE_COUNT: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamPolicyReturnClass {
    Positive = 0,
    Zero = 1,
    Negative = 2,
}

const STREAM_POLICY_RETURN_COUNT: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamPolicyErrnoClass {
    None = 0,
    Eintr = 1,
    Again = 2,
    Other = 3,
}

const STREAM_POLICY_ERRNO_COUNT: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamPolicyAction {
    Retry,
    Buffer,
    Flush,
    Escalate,
    Yield,
}

const STREAM_POLICY_TABLE: [[[StreamPolicyAction; STREAM_POLICY_ERRNO_COUNT];
    STREAM_POLICY_RETURN_COUNT]; STREAM_POLICY_STATE_COUNT] = [
    // Read
    [
        [StreamPolicyAction::Buffer; STREAM_POLICY_ERRNO_COUNT],
        [StreamPolicyAction::Yield; STREAM_POLICY_ERRNO_COUNT],
        [
            StreamPolicyAction::Escalate,
            StreamPolicyAction::Retry,
            StreamPolicyAction::Yield,
            StreamPolicyAction::Escalate,
        ],
    ],
    // Write
    [
        [StreamPolicyAction::Flush; STREAM_POLICY_ERRNO_COUNT],
        [StreamPolicyAction::Escalate; STREAM_POLICY_ERRNO_COUNT],
        [
            StreamPolicyAction::Escalate,
            StreamPolicyAction::Retry,
            StreamPolicyAction::Yield,
            StreamPolicyAction::Escalate,
        ],
    ],
    // Seek
    [
        [StreamPolicyAction::Flush; STREAM_POLICY_ERRNO_COUNT],
        [StreamPolicyAction::Flush; STREAM_POLICY_ERRNO_COUNT],
        [
            StreamPolicyAction::Escalate,
            StreamPolicyAction::Retry,
            StreamPolicyAction::Escalate,
            StreamPolicyAction::Escalate,
        ],
    ],
    // Close
    [
        [StreamPolicyAction::Flush; STREAM_POLICY_ERRNO_COUNT],
        [StreamPolicyAction::Flush; STREAM_POLICY_ERRNO_COUNT],
        [
            StreamPolicyAction::Escalate,
            StreamPolicyAction::Retry,
            StreamPolicyAction::Yield,
            StreamPolicyAction::Escalate,
        ],
    ],
];

#[inline]
fn classify_stream_return(rc: isize) -> StreamPolicyReturnClass {
    if rc > 0 {
        StreamPolicyReturnClass::Positive
    } else if rc == 0 {
        StreamPolicyReturnClass::Zero
    } else {
        StreamPolicyReturnClass::Negative
    }
}

#[inline]
fn classify_stream_errno(errno_val: c_int) -> StreamPolicyErrnoClass {
    if errno_val == 0 {
        StreamPolicyErrnoClass::None
    } else if errno_val == errno::EINTR {
        StreamPolicyErrnoClass::Eintr
    } else if errno_val == errno::EAGAIN || errno_val == libc::EWOULDBLOCK {
        StreamPolicyErrnoClass::Again
    } else {
        StreamPolicyErrnoClass::Other
    }
}

#[inline]
fn stream_policy_action(
    state: StreamPolicyState,
    rc: isize,
    errno_val: c_int,
) -> StreamPolicyAction {
    let state_ix = state as usize;
    let return_ix = classify_stream_return(rc) as usize;
    let errno_ix = classify_stream_errno(errno_val) as usize;
    STREAM_POLICY_TABLE[state_ix][return_ix][errno_ix]
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
    ensure_host_libio_exit_safe();

    use std::sync::atomic::{AtomicPtr, Ordering};
    static PTR: AtomicPtr<Mutex<StreamRegistry>> = AtomicPtr::new(std::ptr::null_mut());
    static INIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let p = PTR.load(Ordering::Acquire);
    if !p.is_null() {
        return unsafe { &*p };
    }
    // First call — initialize without futex.
    if INIT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
    {
        let reg = Box::new(Mutex::new(StreamRegistry::new()));
        PTR.store(Box::into_raw(reg), Ordering::Release);
        return unsafe { &*PTR.load(Ordering::Acquire) };
    }
    // Another thread is initializing — spin wait (no futex).
    loop {
        let p = PTR.load(Ordering::Acquire);
        if !p.is_null() {
            return unsafe { &*p };
        }
        std::hint::spin_loop();
    }
}

fn registry_contains_stream(id: usize) -> bool {
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.contains_key(&id)
}

#[derive(Clone, Copy, Debug)]
struct HostStreamState {
    io_started: bool,
}

fn host_stream_registry() -> &'static Mutex<HashMap<usize, HostStreamState>> {
    static HOST_STREAMS: OnceLock<Mutex<HashMap<usize, HostStreamState>>> = OnceLock::new();
    HOST_STREAMS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register_host_stream(stream: *mut c_void) {
    if stream.is_null() {
        return;
    }
    let id = canonical_stream_id(stream);
    if registry_contains_stream(id) {
        return;
    }
    let mut guard = host_stream_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    guard
        .entry(id)
        .or_insert(HostStreamState { io_started: false });
}

fn mark_host_io_started(stream: *mut c_void) {
    if stream.is_null() {
        return;
    }
    let id = canonical_stream_id(stream);
    if registry_contains_stream(id) {
        return;
    }
    let mut guard = host_stream_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    guard
        .entry(id)
        .and_modify(|state| state.io_started = true)
        .or_insert(HostStreamState { io_started: true });
}

fn host_stream_io_started(id: usize) -> bool {
    let guard = host_stream_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    guard
        .get(&id)
        .map(|state| state.io_started)
        .unwrap_or(false)
}

fn unregister_host_stream(stream: *mut c_void) {
    if stream.is_null() {
        return;
    }
    let id = canonical_stream_id(stream);
    let mut guard = host_stream_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    guard.remove(&id);
}

#[inline]
fn standard_stream_id(stream: *mut c_void) -> Option<usize> {
    if stream.is_null() {
        return None;
    }
    let addr = stream as usize;
    if addr == STDIN_SENTINEL
        || stream == io_internal_abi::native_stdio_stream_ptr(libc::STDIN_FILENO)
    {
        return Some(STDIN_SENTINEL);
    }
    if addr == STDOUT_SENTINEL
        || stream == io_internal_abi::native_stdio_stream_ptr(libc::STDOUT_FILENO)
    {
        return Some(STDOUT_SENTINEL);
    }
    if addr == STDERR_SENTINEL
        || stream == io_internal_abi::native_stdio_stream_ptr(libc::STDERR_FILENO)
    {
        return Some(STDERR_SENTINEL);
    }
    None
}

#[inline]
fn canonical_stream_id(stream: *mut c_void) -> usize {
    standard_stream_id(stream).unwrap_or(stream as usize)
}

#[inline]
fn sync_native_stdio_buffering(stream: *mut c_void, mode: BufMode, buf: *mut c_char, size: usize) {
    let Some(fd) = (match standard_stream_id(stream) {
        Some(STDIN_SENTINEL) => Some(libc::STDIN_FILENO),
        Some(STDOUT_SENTINEL) => Some(libc::STDOUT_FILENO),
        Some(STDERR_SENTINEL) => Some(libc::STDERR_FILENO),
        _ => None,
    }) else {
        return;
    };
    // SAFETY: buf (if non-null) comes from the caller with `size` bytes of storage.
    let _ = unsafe {
        io_internal_abi::configure_native_stdio_stream(
            fd,
            native_file_buf_mode(mode),
            buf.cast(),
            size,
        )
    };
}

#[inline]
unsafe fn host_stdio_symbol(slot: &OnceLock<usize>, symbol: &'static str) -> Option<usize> {
    crate::host_resolve::resolve_host_symbol_cached(slot, symbol)
}

#[inline]
unsafe fn sync_host_errno(default_errno: c_int) {
    unsafe { set_abi_errno(crate::host_resolve::host_errno(default_errno)) };
}

#[inline]
unsafe fn host_fwrite_fn() -> Option<HostFwriteFn> {
    unsafe { host_stdio_symbol(&HOST_FWRITE_FN, "fwrite") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_fputs_fn() -> Option<HostFputsFn> {
    unsafe { host_stdio_symbol(&HOST_FPUTS_FN, "fputs") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_fputc_fn() -> Option<HostFputcFn> {
    unsafe { host_stdio_symbol(&HOST_FPUTC_FN, "fputc") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_fclose_fn() -> Option<HostFcloseFn> {
    unsafe { host_stdio_symbol(&HOST_FCLOSE_FN, "fclose") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_fileno_fn() -> Option<HostFilenoFn> {
    unsafe { host_stdio_symbol(&HOST_FILENO_FN, "fileno") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_feof_fn() -> Option<HostFeofFn> {
    unsafe { host_stdio_symbol(&HOST_FEOF_FN, "feof") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_ferror_fn() -> Option<HostFerrorFn> {
    unsafe { host_stdio_symbol(&HOST_FERROR_FN, "ferror") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_clearerr_fn() -> Option<HostClearerrFn> {
    unsafe { host_stdio_symbol(&HOST_CLEARERR_FN, "clearerr") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_fgetc_fn() -> Option<HostFgetcFn> {
    unsafe { host_stdio_symbol(&HOST_FGETC_FN, "fgetc") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_fgets_fn() -> Option<HostFgetsFn> {
    unsafe { host_stdio_symbol(&HOST_FGETS_FN, "fgets") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_fread_fn() -> Option<HostFreadFn> {
    unsafe { host_stdio_symbol(&HOST_FREAD_FN, "fread") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_ungetc_fn() -> Option<HostUngetcFn> {
    unsafe { host_stdio_symbol(&HOST_UNGETC_FN, "ungetc") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_fseek_fn() -> Option<HostFseekFn> {
    unsafe { host_stdio_symbol(&HOST_FSEEK_FN, "fseek") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_ftell_fn() -> Option<HostFtellFn> {
    unsafe { host_stdio_symbol(&HOST_FTELL_FN, "ftell") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_fflush_fn() -> Option<HostFflushFn> {
    unsafe { host_stdio_symbol(&HOST_FFLUSH_FN, "fflush") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_getdelim_fn() -> Option<HostGetdelimFn> {
    unsafe { host_stdio_symbol(&HOST_GETDELIM_FN, "getdelim") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_getline_fn() -> Option<HostGetlineFn> {
    unsafe { host_stdio_symbol(&HOST_GETLINE_FN, "getline") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_setvbuf_fn() -> Option<HostSetvbufFn> {
    unsafe { host_stdio_symbol(&HOST_SETVBUF_FN, "setvbuf") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_vfscanf_fn() -> Option<HostVfscanfFn> {
    unsafe { host_stdio_symbol(&HOST_VFSCANF_FN, "vfscanf") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_fgetpos_fn() -> Option<HostFgetposFn> {
    unsafe { host_stdio_symbol(&HOST_FGETPOS_FN, "fgetpos") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_fsetpos_fn() -> Option<HostFsetposFn> {
    unsafe { host_stdio_symbol(&HOST_FSETPOS_FN, "fsetpos") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_freopen_fn() -> Option<HostFreopenFn> {
    unsafe { host_stdio_symbol(&HOST_FREOPEN_FN, "freopen") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_flockfile_fn() -> Option<HostFlockfileFn> {
    unsafe { host_stdio_symbol(&HOST_FLOCKFILE_FN, "flockfile") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_funlockfile_fn() -> Option<HostFunlockfileFn> {
    unsafe { host_stdio_symbol(&HOST_FUNLOCKFILE_FN, "funlockfile") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
unsafe fn host_ftrylockfile_fn() -> Option<HostFtrylockfileFn> {
    unsafe { host_stdio_symbol(&HOST_FTRYLOCKFILE_FN, "ftrylockfile") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

fn alloc_stream_id() -> usize {
    let mut next = NEXT_STREAM_ID.lock().unwrap_or_else(|e| e.into_inner());
    let id = *next;
    *next = id.wrapping_add(1);
    id
}

fn native_stream_open_flags(open_flags: OpenFlags) -> u32 {
    let mut flags = 0u32;
    if open_flags.readable {
        flags |= io_internal_abi::file_flags::READ;
    }
    if open_flags.writable {
        flags |= io_internal_abi::file_flags::WRITE;
    }
    if open_flags.append {
        flags |= io_internal_abi::file_flags::APPEND;
    }
    flags
}

fn maybe_unregister_dynamic_native_stream(stream: *mut c_void) {
    if let Some(slot) = io_internal_abi::verify_native_file(stream)
        && slot >= 3
    {
        let mut native_reg = io_internal_abi::native_stream_registry();
        let _ = native_reg.unregister(slot);
    }
}

pub(crate) fn register_memory_stream_with_native_handle(
    stream: StdioStream,
    backing: io_internal_abi::NativeFileBacking,
    open_flags: OpenFlags,
) -> *mut c_void {
    let file = io_internal_abi::NativeFile::new_with_backing(
        backing,
        native_stream_open_flags(open_flags),
        NativeFileBufMode::None,
    );
    let mut native_reg = io_internal_abi::native_stream_registry();
    let Some(slot) = native_reg.register(file) else {
        unsafe { set_abi_errno(errno::EMFILE) };
        return std::ptr::null_mut();
    };
    let native_ptr = match native_reg.get_mut(slot) {
        Some(file) => file as *mut io_internal_abi::NativeFile as *mut c_void,
        None => {
            unsafe { set_abi_errno(errno::EMFILE) };
            return std::ptr::null_mut();
        }
    };
    io_internal_abi::register_native_file_ptr(native_ptr);
    drop(native_reg);

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.insert(native_ptr as usize, stream);
    native_ptr
}

#[allow(dead_code)]
pub(crate) fn register_stream(stream: StdioStream) -> usize {
    let id = alloc_stream_id();
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.insert(id, stream);
    id
}

pub(crate) fn stream_id_from_handle(stream: *mut c_void) -> usize {
    canonical_stream_id(stream)
}

#[inline]
fn stream_exists(id: usize) -> bool {
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.contains_key(&id)
}

unsafe fn write_bytes_without_runtime_policy(
    id: usize,
    stream: *mut c_void,
    bytes: &[u8],
) -> usize {
    if bytes.is_empty() {
        return 0;
    }

    if is_cookie_stream(id) {
        if !stream_exists(id) {
            return 0;
        }

        let mut written_total = 0usize;
        while written_total < bytes.len() {
            let rc = unsafe {
                cookie_stream_write(
                    id,
                    bytes[written_total..].as_ptr(),
                    bytes.len().saturating_sub(written_total),
                )
            };
            let errno_val = if rc < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            } else {
                0
            };
            match stream_policy_action(StreamPolicyState::Write, rc, errno_val) {
                StreamPolicyAction::Retry => continue,
                StreamPolicyAction::Yield | StreamPolicyAction::Escalate => break,
                StreamPolicyAction::Flush | StreamPolicyAction::Buffer => {}
            }
            if rc <= 0 {
                break;
            }
            let advanced = (rc as usize).min(bytes.len() - written_total);
            if advanced == 0 {
                break;
            }
            written_total += advanced;
        }

        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(stream_obj) = reg.streams.get_mut(&id) {
            let delta = written_total.min(i64::MAX as usize) as i64;
            stream_obj.set_offset(stream_obj.offset().saturating_add(delta));
            if written_total < bytes.len() {
                stream_obj.set_error();
            }
        }
        return written_total;
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream_obj) = reg.streams.get_mut(&id) else {
        drop(reg);
        if let Some(host_fwrite) = unsafe { host_fwrite_fn() } {
            let written = unsafe { host_fwrite(bytes.as_ptr().cast(), 1, bytes.len(), stream) };
            if written == 0 {
                unsafe { sync_host_errno(0) };
            } else {
                mark_host_io_started(stream);
            }
            return written.min(bytes.len());
        }
        return 0;
    };

    if stream_obj.is_mem_backed() {
        let written = stream_obj.mem_write(bytes);
        if written > 0 {
            let start = stream_obj.offset().saturating_sub(written as i64);
            if start >= 0 {
                unsafe { sync_fmemopen_write(id, start as usize, &bytes[..written]) };
            }
        }
        if written < bytes.len() {
            stream_obj.set_error();
        }
        return written;
    }

    let write_result = match stream_obj.buffer_write(bytes) {
        Some(result) => result,
        None => return 0,
    };
    let flushed_from_buffer = write_result.flushed_from_buffer;
    let total_written = if write_result.flush_needed {
        let fd = stream_obj.fd();
        let mut written = 0usize;
        let mut success = true;
        while written < write_result.flush_data.len() {
            let rc = unsafe {
                sys_write_fd(
                    fd,
                    write_result.flush_data[written..].as_ptr().cast(),
                    write_result.flush_data.len() - written,
                )
            };
            let errno_val = if rc < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            } else {
                0
            };
            match stream_policy_action(StreamPolicyState::Write, rc, errno_val) {
                StreamPolicyAction::Retry => continue,
                StreamPolicyAction::Yield | StreamPolicyAction::Escalate => {
                    success = false;
                    break;
                }
                StreamPolicyAction::Flush | StreamPolicyAction::Buffer => {}
            }
            if rc == 0 {
                success = false;
                break;
            }
            written += rc as usize;
        }

        if success {
            let flushed_new = write_result
                .flush_data
                .len()
                .saturating_sub(flushed_from_buffer);
            write_result.buffered.saturating_add(flushed_new)
        } else {
            stream_obj.set_error();
            stream_obj.mark_flushed();
            let flushed_new = written.saturating_sub(flushed_from_buffer);
            if flushed_new > 0 {
                stream_obj.set_offset(stream_obj.offset().saturating_add(flushed_new as i64));
            }
            return flushed_new;
        }
    } else {
        write_result.buffered
    };

    if total_written > 0 {
        stream_obj.set_offset(stream_obj.offset().saturating_add(total_written as i64));
    }
    total_written
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
        let errno_val = if rc < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        match stream_policy_action(StreamPolicyState::Write, rc, errno_val) {
            StreamPolicyAction::Retry => continue,
            StreamPolicyAction::Yield | StreamPolicyAction::Escalate => {
                stream.set_error();
                return false;
            }
            StreamPolicyAction::Flush | StreamPolicyAction::Buffer => {}
        }
        if rc == 0 {
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
    loop {
        let rc = unsafe { sys_read_fd(fd, tmp.as_mut_ptr().cast(), tmp.len()) };
        let errno_val = if rc < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        match stream_policy_action(StreamPolicyState::Read, rc, errno_val) {
            StreamPolicyAction::Retry => continue,
            StreamPolicyAction::Buffer => {
                stream.fill_read_buffer(&tmp[..rc as usize]);
                return rc;
            }
            StreamPolicyAction::Yield => {
                if rc == 0 {
                    stream.set_eof();
                }
                return 0;
            }
            StreamPolicyAction::Escalate => {
                stream.set_error();
                return -1;
            }
            StreamPolicyAction::Flush => {
                if rc > 0 {
                    stream.fill_read_buffer(&tmp[..rc as usize]);
                    return rc;
                }
                return 0;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// stdin / stdout / stderr accessors
// ---------------------------------------------------------------------------

/// Global `stdin` pointer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static mut stdin: *mut c_void = STDIN_SENTINEL as *mut c_void;

/// Global `stdout` pointer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static mut stdout: *mut c_void = STDOUT_SENTINEL as *mut c_void;

/// Global `stderr` pointer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static mut stderr: *mut c_void = STDERR_SENTINEL as *mut c_void;

// glibc internal `_IO_2_1_{stdin,stdout,stderr}_` aliases.
//
// Some binaries resolve these names directly instead of going through the
// public `stdin/stdout/stderr` globals. Release builds export them as true
// linker aliases to those globals, which keeps both names on the exact same
// pointer cell and therefore the exact same NativeFile storage.
//
// Debug/test builds do not export the libc symbol surface, so they keep local
// mirror statics with the same runtime values for unit-test coverage.
#[cfg(debug_assertions)]
#[allow(non_upper_case_globals)]
pub static mut IO_2_1_STDIN: *mut c_void = STDIN_SENTINEL as *mut c_void;

#[cfg(debug_assertions)]
#[allow(non_upper_case_globals)]
pub static mut IO_2_1_STDOUT: *mut c_void = STDOUT_SENTINEL as *mut c_void;

#[cfg(debug_assertions)]
#[allow(non_upper_case_globals)]
pub static mut IO_2_1_STDERR: *mut c_void = STDERR_SENTINEL as *mut c_void;

#[cfg(not(debug_assertions))]
unsafe extern "C" {
    #[link_name = "_IO_2_1_stdin_"]
    pub static mut IO_2_1_STDIN: *mut c_void;
    #[link_name = "_IO_2_1_stdout_"]
    pub static mut IO_2_1_STDOUT: *mut c_void;
    #[link_name = "_IO_2_1_stderr_"]
    pub static mut IO_2_1_STDERR: *mut c_void;
}

#[cfg(not(debug_assertions))]
global_asm!(
    ".global _IO_2_1_stdin_",
    ".type _IO_2_1_stdin_, @object",
    ".set _IO_2_1_stdin_, stdin",
    ".global _IO_2_1_stdout_",
    ".type _IO_2_1_stdout_, @object",
    ".set _IO_2_1_stdout_, stdout",
    ".global _IO_2_1_stderr_",
    ".type _IO_2_1_stderr_, @object",
    ".set _IO_2_1_stderr_, stderr",
);

static HOST_STDIO_BOOTSTRAPPED: AtomicBool = AtomicBool::new(false);
static HOST_LIBIO_EXIT_PATCHED: AtomicBool = AtomicBool::new(false);

fn ensure_host_libio_exit_safe() {
    if !HOST_LIBIO_EXIT_PATCHED.swap(true, Ordering::AcqRel) {
        unsafe { io_internal_abi::bootstrap_host_libio_exports() };
    }
}

/// Internal stream id for stdin-backed scanf helpers.
#[inline]
pub(crate) const fn stdin_stream_id() -> usize {
    STDIN_SENTINEL
}

#[inline]
fn active_stdout_stream() -> *mut c_void {
    // SAFETY: reading the exported `stdout` global is required to keep
    // output helpers coherent with later `fflush(stdout)` and redirection.
    unsafe {
        if stdout.is_null() {
            io_internal_abi::native_stdio_stream_ptr(libc::STDOUT_FILENO)
        } else {
            stdout
        }
    }
}

#[cfg(not(debug_assertions))]
unsafe fn sync_copy_relocated_stdio_symbol(
    symbol: &CStr,
    owned_cell: *mut *mut c_void,
    value: *mut c_void,
) {
    type DlsymFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;

    let Some(addr) = crate::host_resolve::resolve_host_symbol_raw("dlsym") else {
        return;
    };
    // SAFETY: raw resolver returns the host glibc dlsym with the expected ABI.
    let host_dlsym: DlsymFn = unsafe { core::mem::transmute(addr) };
    // SAFETY: data-symbol dlsym returns the address of the writable symbol cell.
    let mut resolved_cell = unsafe { host_dlsym(std::ptr::null_mut(), symbol.as_ptr()) };
    if resolved_cell.is_null() {
        resolved_cell = unsafe { host_dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
    }
    let resolved_cell = resolved_cell.cast::<*mut c_void>();
    if resolved_cell.is_null() || resolved_cell == owned_cell {
        return;
    }
    // SAFETY: RTLD_DEFAULT resolved a writable copy-relocated symbol cell with
    // the same `FILE *` layout as our exported globals.
    unsafe { resolved_cell.write(value) };
}

/// Publish FrankenLibC-owned stdio globals and mark host stdio delegation ready.
pub(crate) fn init_host_stdio_streams() {
    ensure_host_libio_exit_safe();

    let stdin_ptr = io_internal_abi::native_stdio_stream_ptr(libc::STDIN_FILENO);
    let stdout_ptr = io_internal_abi::native_stdio_stream_ptr(libc::STDOUT_FILENO);
    let stderr_ptr = io_internal_abi::native_stdio_stream_ptr(libc::STDERR_FILENO);
    if !stdin_ptr.is_null() && !stdout_ptr.is_null() && !stderr_ptr.is_null() {
        unsafe {
            stdin = stdin_ptr;
            stdout = stdout_ptr;
            stderr = stderr_ptr;
            #[cfg(debug_assertions)]
            {
                IO_2_1_STDIN = stdin_ptr;
                IO_2_1_STDOUT = stdout_ptr;
                IO_2_1_STDERR = stderr_ptr;
            }
            #[cfg(not(debug_assertions))]
            {
                sync_copy_relocated_stdio_symbol(
                    c"stdin",
                    core::ptr::addr_of_mut!(stdin),
                    stdin_ptr,
                );
                sync_copy_relocated_stdio_symbol(
                    c"stdout",
                    core::ptr::addr_of_mut!(stdout),
                    stdout_ptr,
                );
                sync_copy_relocated_stdio_symbol(
                    c"stderr",
                    core::ptr::addr_of_mut!(stderr),
                    stderr_ptr,
                );
                sync_copy_relocated_stdio_symbol(
                    c"_IO_2_1_stdin_",
                    core::ptr::addr_of_mut!(stdin),
                    stdin_ptr,
                );
                sync_copy_relocated_stdio_symbol(
                    c"_IO_2_1_stdout_",
                    core::ptr::addr_of_mut!(stdout),
                    stdout_ptr,
                );
                sync_copy_relocated_stdio_symbol(
                    c"_IO_2_1_stderr_",
                    core::ptr::addr_of_mut!(stderr),
                    stderr_ptr,
                );
            }
        }
    }
    HOST_STDIO_BOOTSTRAPPED.store(true, Ordering::Release);
}

#[doc(hidden)]
pub fn init_host_stdio_streams_for_tests() {
    init_host_stdio_streams();
}

// ---------------------------------------------------------------------------
// fopen / fclose
// ---------------------------------------------------------------------------

/// POSIX `fopen`.
///
/// Opens a file and returns an opaque stream handle managed by the ABI registry.
/// Uses raw syscalls exclusively - no host delegation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fopen(pathname: *const c_char, mode: *const c_char) -> *mut c_void {
    if pathname.is_null() || mode.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    let (safety_mode, decision) =
        runtime_policy::decide(ApiFamily::Stdio, pathname as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(safety_mode.heals_enabled(), decision.action);

    // Validate pathname string.
    let (_path_len, path_terminated) = unsafe {
        scan_c_str_len(
            pathname,
            if repair {
                known_remaining(pathname as usize)
            } else {
                None
            },
        )
    };
    if !path_terminated && repair {
        unsafe { set_abi_errno(errno::ENAMETOOLONG) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    // Validate mode string.
    let (mode_len, mode_terminated) = unsafe {
        scan_c_str_len(
            mode,
            if repair {
                known_remaining(mode as usize)
            } else {
                None
            },
        )
    };
    if !mode_terminated {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    let mode_bytes = unsafe { std::slice::from_raw_parts(mode as *const u8, mode_len) };
    let Some(open_flags) = parse_mode(mode_bytes) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return std::ptr::null_mut();
    };

    // Convert to libc open flags and open the file.
    let oflags = flags_to_oflags(&open_flags);
    let create_mode: libc::mode_t = 0o666;
    let fd = match unsafe {
        raw_syscall::sys_openat(libc::AT_FDCWD, pathname as *const u8, oflags, create_mode)
    } {
        Ok(f) => f,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
            return std::ptr::null_mut();
        }
    };

    // Create stream via fdopen_native_impl.
    let fp = fdopen_native_impl(fd, &open_flags);
    if fp.is_null() {
        // fdopen_native_impl failed (registry full) - close the fd we opened.
        let _ = raw_syscall::sys_close(fd);
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
    } else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, false);
    }
    fp
}

/// Internal: create a `StdioStream` for an already-open fd.
///
/// Returns an opaque stream pointer. The fd remains owned by the caller on
/// failure; this function never closes it.
fn fdopen_native_impl(fd: c_int, open_flags: &OpenFlags) -> *mut c_void {
    // Determine buffering mode via raw isatty check (TIOCGWINSZ ioctl).
    let buf_mode = if fd == libc::STDERR_FILENO {
        BufMode::None
    } else if raw_isatty(fd) {
        BufMode::Line
    } else {
        BufMode::Full
    };

    // Create StdioStream and set initial offset for append mode.
    let mut stream = StdioStream::with_mode(fd, *open_flags, buf_mode);
    if open_flags.append
        && let Ok(end_off) = raw_syscall::sys_lseek(fd, 0, libc::SEEK_END)
    {
        stream.set_offset(end_off);
    }

    // Register in the StdioStream registry.
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let mut id = alloc_stream_id();
    let start = id;
    while reg.streams.contains_key(&id) {
        id = alloc_stream_id();
        if id == start {
            unsafe { set_abi_errno(errno::EMFILE) };
            return std::ptr::null_mut();
        }
    }
    reg.streams.insert(id, stream);
    id as *mut c_void
}

/// Raw isatty check using TIOCGWINSZ ioctl syscall.
///
/// Returns true if fd is a terminal, false otherwise.
#[inline]
fn raw_isatty(fd: c_int) -> bool {
    let mut ws = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    let rc = unsafe {
        frankenlibc_core::syscall::sys_ioctl(
            fd,
            libc::TIOCGWINSZ as usize,
            ws.as_mut_ptr() as usize,
        )
    };
    rc.is_ok()
}

/// POSIX `fclose`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fclose(stream: *mut c_void) -> c_int {
    let id = canonical_stream_id(stream);
    if id == 0 {
        return libc::EOF;
    }
    if !registry_contains_stream(id)
        && let Some(host_fclose) = unsafe { host_fclose_fn() }
    {
        let rc = unsafe { host_fclose(stream) };
        if rc != 0 {
            unsafe { sync_host_errno(errno::EBADF) };
        } else {
            unregister_host_stream(stream);
        }
        return rc;
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
        unsafe {
            sync_memstream_to_caller(id, &s);
            sync_fmemopen_full(id, &s);
            crate::wchar_abi::sync_open_wmemstream_to_caller(id, &s);
        }
        // Remove sync metadata for open_memstream.
        let mut sync_guard = mem_sync_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut map) = *sync_guard {
            map.remove(&id);
        }
        // Remove sync metadata for fmemopen fixed buffers.
        let mut fixed_guard = mem_fixed_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(ref mut map) = *fixed_guard {
            map.remove(&id);
        }
        crate::wchar_abi::unregister_open_wmemstream(id);
        maybe_unregister_dynamic_native_stream(stream);
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
    if fd >= 0
        && id != STDIN_SENTINEL
        && id != STDOUT_SENTINEL
        && id != STDERR_SENTINEL
        && raw_syscall::sys_close(fd).is_err()
    {
        adverse = true;
    }

    maybe_unregister_dynamic_native_stream(stream);
    if adverse { libc::EOF } else { 0 }
}

// ---------------------------------------------------------------------------
// fflush
// ---------------------------------------------------------------------------

/// POSIX `fflush`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fflush(stream: *mut c_void) -> c_int {
    if !stream.is_null() {
        let id = canonical_stream_id(stream);
        if !registry_contains_stream(id)
            && let Some(host_fflush) = unsafe { host_fflush_fn() }
        {
            let rc = unsafe { host_fflush(stream) };
            if rc != 0 {
                unsafe { sync_host_errno(errno::EBADF) };
            }
            return rc;
        }
    }
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        canonical_stream_id(stream),
        0,
        true,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 4, true);
        return libc::EOF;
    }

    // NULL stream: flush all open streams.
    if stream.is_null() {
        let mut host_fail = false;
        if let Some(host_fflush) = unsafe { host_fflush_fn() } {
            let rc = unsafe { host_fflush(std::ptr::null_mut()) };
            if rc != 0 {
                host_fail = true;
                unsafe { sync_host_errno(errno::EBADF) };
            }
        }
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let mut any_fail = false;
        let ids: Vec<usize> = reg.streams.keys().copied().collect();
        for id in ids {
            if let Some(s) = reg.streams.get_mut(&id) {
                let ok = if is_cookie_stream(id) {
                    true
                } else if s.is_mem_backed() {
                    unsafe {
                        sync_memstream_to_caller(id, s);
                        sync_fmemopen_full(id, s);
                        crate::wchar_abi::sync_open_wmemstream_to_caller(id, s);
                    }
                    true
                } else {
                    unsafe { flush_stream(s) }
                };
                if !ok {
                    any_fail = true;
                }
            }
        }
        let failed = any_fail || host_fail;
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 20, failed);
        return if failed { libc::EOF } else { 0 };
    }

    let id = canonical_stream_id(stream);
    if is_cookie_stream(id) {
        let adverse = !stream_exists(id);
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 8, adverse);
        return if adverse { libc::EOF } else { 0 };
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        // Memory-backed streams: sync data to C caller's pointers (open_memstream).
        if s.is_mem_backed() {
            unsafe {
                sync_memstream_to_caller(id, s);
                sync_fmemopen_full(id, s);
                crate::wchar_abi::sync_open_wmemstream_to_caller(id, s);
            }
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
    let id = canonical_stream_id(stream);
    if !registry_contains_stream(id)
        && let Some(host_fgetc) = unsafe { host_fgetc_fn() }
    {
        let rc = unsafe { host_fgetc(stream) };
        mark_host_io_started(stream);
        if rc == libc::EOF {
            unsafe { sync_host_errno(0) };
        }
        return rc;
    }
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
    let id = canonical_stream_id(stream);
    let byte = c as u8;
    if runtime_policy::bootstrap_passthrough_active() || !runtime_policy::mode().heals_enabled() {
        let bytes = [byte];
        let written = unsafe { write_bytes_without_runtime_policy(id, stream, &bytes) };
        return if written == 1 {
            byte as c_int
        } else {
            libc::EOF
        };
    }

    let _trace_scope = runtime_policy::entrypoint_scope("fputc");
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 1, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    }

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
        drop(reg);
        // Not in our registry — delegate to host libc fputc (real FILE*).
        if let Some(host_fputc) = unsafe { host_fputc_fn() } {
            let rc = unsafe { host_fputc(c, stream) };
            if rc == libc::EOF {
                unsafe { sync_host_errno(0) };
            } else {
                mark_host_io_started(stream);
            }
            return rc;
        }
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
        let start = s.offset().saturating_sub(n as i64);
        if start >= 0 {
            unsafe { sync_fmemopen_write(id, start as usize, &[byte][..n]) };
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
        return c;
    }

    let write_result = match s.buffer_write(&[byte]) {
        Some(result) => result,
        None => {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 8, true);
            return libc::EOF;
        }
    };

    let flushed_from_buffer = write_result.flushed_from_buffer;
    let total_written = if write_result.flush_needed {
        let fd = s.fd();
        let mut written = 0usize;
        let mut success = true;
        while written < write_result.flush_data.len() {
            let rc = unsafe {
                sys_write_fd(
                    fd,
                    write_result.flush_data[written..].as_ptr().cast(),
                    write_result.flush_data.len() - written,
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
            let flushed_new = write_result
                .flush_data
                .len()
                .saturating_sub(flushed_from_buffer);
            write_result.buffered.saturating_add(flushed_new)
        } else {
            s.set_error();
            s.mark_flushed();
            let flushed_new = written.saturating_sub(flushed_from_buffer);
            if flushed_new > 0 {
                s.set_offset(s.offset().saturating_add(flushed_new as i64));
            }
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 8, true);
            return libc::EOF;
        }
    } else {
        write_result.buffered
    };

    if total_written > 0 {
        s.set_offset(s.offset().saturating_add(total_written as i64));
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
    let id = canonical_stream_id(stream);
    if !registry_contains_stream(id)
        && let Some(host_fgets) = unsafe { host_fgets_fn() }
    {
        let rc = unsafe { host_fgets(buf, size, stream) };
        if rc.is_null() {
            unsafe { sync_host_errno(0) };
        } else {
            mark_host_io_started(stream);
        }
        return rc;
    }
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

    let id = canonical_stream_id(stream);
    if runtime_policy::bootstrap_passthrough_active() || !runtime_policy::mode().heals_enabled() {
        let (len, _) = unsafe { scan_c_str_len(s, None) };
        let bytes = unsafe { std::slice::from_raw_parts(s as *const u8, len) };
        let written = unsafe { write_bytes_without_runtime_policy(id, stream, bytes) };
        return if written == bytes.len() { 0 } else { libc::EOF };
    }

    let _trace_scope = runtime_policy::entrypoint_scope("fputs");
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
        drop(reg);
        // Not in our registry — delegate to host libc fputs (real FILE*).
        if let Some(host_fputs) = unsafe { host_fputs_fn() } {
            let rc = unsafe { host_fputs(s, stream) };
            if rc == libc::EOF {
                unsafe { sync_host_errno(0) };
            } else {
                mark_host_io_started(stream);
            }
            return if rc == libc::EOF { libc::EOF } else { 0 };
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return libc::EOF;
    };

    if stream_obj.is_mem_backed() {
        let written = stream_obj.mem_write(bytes);
        if written > 0 {
            let start = stream_obj.offset().saturating_sub(written as i64);
            if start >= 0 {
                unsafe { sync_fmemopen_write(id, start as usize, &bytes[..written]) };
            }
        }
        let adverse = written < bytes.len();
        if adverse {
            stream_obj.set_error();
        }
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(10, len),
            adverse,
        );
        return if adverse { libc::EOF } else { 0 };
    }

    let write_result = match stream_obj.buffer_write(bytes) {
        Some(result) => result,
        None => {
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(10, len),
                true,
            );
            return libc::EOF;
        }
    };
    let flushed_from_buffer = write_result.flushed_from_buffer;
    let total_written = if write_result.flush_needed {
        let fd = stream_obj.fd();
        let mut written = 0usize;
        let mut success = true;
        while written < write_result.flush_data.len() {
            let rc = unsafe {
                sys_write_fd(
                    fd,
                    write_result.flush_data[written..].as_ptr().cast(),
                    write_result.flush_data.len() - written,
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
            let flushed_new = write_result
                .flush_data
                .len()
                .saturating_sub(flushed_from_buffer);
            write_result.buffered.saturating_add(flushed_new)
        } else {
            stream_obj.set_error();
            stream_obj.mark_flushed();
            let flushed_new = written.saturating_sub(flushed_from_buffer);
            if flushed_new > 0 {
                stream_obj.set_offset(stream_obj.offset().saturating_add(flushed_new as i64));
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(10, len),
                true,
            );
            return libc::EOF;
        }
    } else {
        write_result.buffered
    };

    if total_written > 0 {
        stream_obj.set_offset(stream_obj.offset().saturating_add(total_written as i64));
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

    let id = canonical_stream_id(stream);
    if !registry_contains_stream(id)
        && let Some(host_fread) = unsafe { host_fread_fn() }
    {
        let rc = unsafe { host_fread(ptr, size, nmemb, stream) };
        mark_host_io_started(stream);
        if rc == 0 {
            unsafe { sync_host_errno(0) };
        }
        return rc;
    }
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, total, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(15, total),
            true,
        );
        return 0;
    }
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
            let errno_val = if rc < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            } else {
                0
            };
            match stream_policy_action(StreamPolicyState::Read, rc, errno_val) {
                StreamPolicyAction::Retry => continue,
                StreamPolicyAction::Escalate => {
                    had_error = true;
                    break;
                }
                StreamPolicyAction::Yield => {
                    reached_eof = rc == 0;
                    break;
                }
                StreamPolicyAction::Buffer | StreamPolicyAction::Flush => {}
            }
            if rc > 0 {
                let advanced = (rc as usize).min(total - read_total);
                if advanced == 0 {
                    had_error = true;
                    break;
                }
                read_total += advanced;
                continue;
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
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(15, total),
            n < total,
        );
        return n.checked_div(size).unwrap_or(0);
    }

    while read_total < total {
        // Prefer direct fd reads to avoid recursive memcpy interposition through
        // buffered internals under LD_PRELOAD.
        let fd = s.fd();
        let to_read = total - read_total;
        let rc = unsafe { sys_read_fd(fd, dst[read_total..].as_mut_ptr().cast(), to_read) };
        let errno_val = if rc < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        match stream_policy_action(StreamPolicyState::Read, rc, errno_val) {
            StreamPolicyAction::Retry => continue,
            StreamPolicyAction::Buffer | StreamPolicyAction::Flush => {
                let bytes_read = rc as usize;
                read_total += bytes_read;
                s.set_offset(s.offset().saturating_add(bytes_read as i64));
                continue;
            }
            StreamPolicyAction::Yield => {
                if rc == 0 {
                    s.set_eof();
                }
                break;
            }
            StreamPolicyAction::Escalate => {
                s.set_error();
                break;
            }
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

    let id = canonical_stream_id(stream);
    let src = unsafe { std::slice::from_raw_parts(ptr as *const u8, total) };
    if runtime_policy::bootstrap_passthrough_active() || !runtime_policy::mode().heals_enabled() {
        let written = unsafe { write_bytes_without_runtime_policy(id, stream, src) };
        return written.checked_div(size).unwrap_or(0);
    }

    let _trace_scope = runtime_policy::entrypoint_scope("fwrite");
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, total, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return 0;
    }

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
            let errno_val = if rc < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            } else {
                0
            };
            match stream_policy_action(StreamPolicyState::Write, rc, errno_val) {
                StreamPolicyAction::Retry => continue,
                StreamPolicyAction::Yield | StreamPolicyAction::Escalate => break,
                StreamPolicyAction::Flush | StreamPolicyAction::Buffer => {}
            }
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
        drop(reg);
        // Not in our registry — delegate to host libc fwrite (real FILE*).
        if let Some(host_fwrite) = unsafe { host_fwrite_fn() } {
            let rc = unsafe { host_fwrite(ptr, size, nmemb, stream) };
            if rc == 0 {
                unsafe { sync_host_errno(0) };
            } else {
                mark_host_io_started(stream);
            }
            return rc;
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return 0;
    };

    // Memory-backed streams: write directly to the backing.
    if s.is_mem_backed() {
        let written = s.mem_write(src);
        if written > 0 {
            let start = s.offset().saturating_sub(written as i64);
            if start >= 0 {
                unsafe { sync_fmemopen_write(id, start as usize, &src[..written]) };
            }
        }
        let complete_items = written.checked_div(size).unwrap_or(0);
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(15, total),
            written < total,
        );
        return complete_items;
    }

    let write_result = match s.buffer_write(src) {
        Some(result) => result,
        None => {
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total),
                true,
            );
            return 0;
        }
    };

    let flushed_from_buffer = write_result.flushed_from_buffer;
    let total_written = if write_result.flush_needed {
        let fd = s.fd();
        let mut written = 0usize;
        let mut success = true;
        while written < write_result.flush_data.len() {
            let rc = unsafe {
                sys_write_fd(
                    fd,
                    write_result.flush_data[written..].as_ptr().cast(),
                    write_result.flush_data.len() - written,
                )
            };
            let errno_val = if rc < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            } else {
                0
            };
            match stream_policy_action(StreamPolicyState::Write, rc, errno_val) {
                StreamPolicyAction::Retry => continue,
                StreamPolicyAction::Yield | StreamPolicyAction::Escalate => {
                    success = false;
                    break;
                }
                StreamPolicyAction::Flush | StreamPolicyAction::Buffer => {}
            }
            if rc == 0 {
                success = false;
                break;
            }
            written += rc as usize;
        }
        if success {
            let flushed_new = write_result
                .flush_data
                .len()
                .saturating_sub(flushed_from_buffer);
            write_result.buffered.saturating_add(flushed_new)
        } else {
            s.set_error();
            s.mark_flushed();
            let flushed_new = written.saturating_sub(flushed_from_buffer);
            if flushed_new > 0 {
                s.set_offset(s.offset().saturating_add(flushed_new as i64));
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total),
                true,
            );
            return flushed_new.checked_div(size).unwrap_or(0);
        }
    } else {
        write_result.buffered
    };

    if total_written > 0 {
        s.set_offset(s.offset().saturating_add(total_written as i64));
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total),
        false,
    );
    total_written.checked_div(size).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// fseek / ftell / rewind
// ---------------------------------------------------------------------------

/// POSIX `fseek`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fseek(stream: *mut c_void, offset: c_long, whence: c_int) -> c_int {
    if stream.is_null() {
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }
    let id = canonical_stream_id(stream);
    if !registry_contains_stream(id)
        && let Some(host_fseek) = unsafe { host_fseek_fn() }
    {
        let rc = unsafe { host_fseek(stream, offset, whence) };
        if rc != 0 {
            unsafe { sync_host_errno(errno::EINVAL) };
        }
        return rc;
    }
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

    let new_off = match raw_syscall::sys_lseek(fd, target_off, target_whence) {
        Ok(off) => off,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
            return -1;
        }
    };

    s.set_offset(new_off);
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, false);
    0
}

/// POSIX `ftell`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftell(stream: *mut c_void) -> c_long {
    if stream.is_null() {
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }
    let id = canonical_stream_id(stream);
    if !registry_contains_stream(id)
        && let Some(host_ftell) = unsafe { host_ftell_fn() }
    {
        let rc = unsafe { host_ftell(stream) };
        if rc < 0 {
            unsafe { sync_host_errno(errno::EINVAL) };
        }
        return rc;
    }
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

    let id = canonical_stream_id(stream);
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
    let id = canonical_stream_id(stream);
    if id == 0 {
        return 0;
    }
    if !registry_contains_stream(id)
        && let Some(host_feof) = unsafe { host_feof_fn() }
    {
        return unsafe { host_feof(stream) };
    }
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
    let id = canonical_stream_id(stream);
    if id == 0 {
        return 0;
    }
    if !registry_contains_stream(id)
        && let Some(host_ferror) = unsafe { host_ferror_fn() }
    {
        return unsafe { host_ferror(stream) };
    }
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
    let id = canonical_stream_id(stream);
    if id == 0 {
        return;
    }
    if !registry_contains_stream(id) {
        if let Some(host_clearerr) = unsafe { host_clearerr_fn() } {
            unsafe { host_clearerr(stream) };
        }
        return;
    }
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
    let id = canonical_stream_id(stream);
    if !registry_contains_stream(id)
        && let Some(host_ungetc) = unsafe { host_ungetc_fn() }
    {
        let rc = unsafe { host_ungetc(c, stream) };
        if rc == libc::EOF {
            unsafe { sync_host_errno(errno::EINVAL) };
        } else {
            mark_host_io_started(stream);
        }
        return rc;
    }
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
    let id = canonical_stream_id(stream);
    if id == 0 {
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }
    if !registry_contains_stream(id)
        && let Some(host_fileno) = unsafe { host_fileno_fn() }
    {
        let rc = unsafe { host_fileno(stream) };
        if rc < 0 {
            unsafe { sync_host_errno(errno::EBADF) };
        }
        return rc;
    }
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get(&id) {
        if s.is_mem_backed() { -1 } else { s.fd() }
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

    let id = canonical_stream_id(stream);
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        // Note: we ignore the caller's buffer pointer; we always use internal allocation.
        if s.set_buffering(buf_mode, size) {
            sync_native_stdio_buffering(stream, buf_mode, _buf, size);
            0
        } else {
            -1
        }
    } else {
        drop(reg);
        if host_stream_io_started(id) {
            unsafe { set_abi_errno(errno::EINVAL) };
            return -1;
        }
        // Not in our registry — delegate to host libc setvbuf (real FILE*).
        if let Some(host_fn) = unsafe { host_setvbuf_fn() } {
            let rc = unsafe { host_fn(stream, _buf, mode, size) };
            if rc != 0 {
                unsafe { sync_host_errno(errno::EBADF) };
            }
            return rc;
        }
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
    unsafe { fputc(c, active_stdout_stream()) }
}

/// POSIX `puts`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    if s.is_null() {
        return libc::EOF;
    }

    if runtime_policy::bootstrap_passthrough_active() || !runtime_policy::mode().heals_enabled() {
        let (len, _) = unsafe { scan_c_str_len(s, None) };
        let stdout_ptr = active_stdout_stream();
        let stdout_id = canonical_stream_id(stdout_ptr);
        let bytes = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), len) };
        let body_written =
            unsafe { write_bytes_without_runtime_policy(stdout_id, stdout_ptr, bytes) };
        let newline_written = body_written == bytes.len()
            && unsafe { write_bytes_without_runtime_policy(stdout_id, stdout_ptr, b"\n") } == 1;
        return if body_written == bytes.len() && newline_written {
            0
        } else {
            libc::EOF
        };
    }

    let _trace_scope = runtime_policy::entrypoint_scope("puts");
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
    let stdout_ptr = active_stdout_stream();
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
    FormatSegment, LengthMod, Precision, ValueArgKind, Width,
    count_printf_args as core_count_printf_args, format_str, parse_format_string,
    positional_printf_arg_plan as core_positional_printf_arg_plan,
};

/// Maximum variadic arguments we extract per printf call.
pub(crate) const MAX_VA_ARGS: usize = 32;

/// Extract variadic arguments from `$args` into `$buf`, guided by `$segments`.
/// Uses a macro to avoid naming the unstable `VaListImpl` type directly.
macro_rules! extract_va_args {
    ($segments:expr, $args:expr, $buf:expr, $extract_count:expr) => {{
        let mut _idx = 0usize;
        if let Some(_plan) = core_positional_printf_arg_plan($segments) {
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
                    // C11 7.21.6.1 para 5: both the '*' width and '*'
                    // precision arguments have type `int`. Read them
                    // as c_int and sign-extend so render_printf's
                    // `as i64` recovers negative values correctly.
                    if spec.width.uses_arg() && _idx < $extract_count {
                        let raw = unsafe { $args.arg::<core::ffi::c_int>() };
                        $buf[_idx] = (raw as i64) as u64;
                        _idx += 1;
                    }
                    if spec.precision.uses_arg() && _idx < $extract_count {
                        let raw = unsafe { $args.arg::<core::ffi::c_int>() };
                        $buf[_idx] = (raw as i64) as u64;
                        _idx += 1;
                    }
                    if spec.value_arg_is_float() && _idx < $extract_count {
                        $buf[_idx] = unsafe { $args.arg::<f64>() }.to_bits();
                        _idx += 1;
                    } else if spec.value_arg_is_gp() && _idx < $extract_count {
                        $buf[_idx] = unsafe { $args.arg::<u64>() };
                        _idx += 1;
                    }
                }
            }
        }
        _idx
    }};
}

/// Convert a printf-produced output length into the printf-family return value.
///
/// POSIX/C11 snprintf (and the related sprintf/vsprintf/vsnprintf family) require
/// the return type `int`. If the number of bytes that *would* be written exceeds
/// `INT_MAX`, POSIX says the call shall fail with `EOVERFLOW` and return -1
/// (C11 7.21.6.5 p2, POSIX.1-2024). Silently casting via `as c_int` truncates —
/// callers that use the return to size buffers would then under-allocate
/// (bd-5t6zo).
#[inline]
fn printf_result_to_c_int(total_len: usize) -> c_int {
    match c_int::try_from(total_len) {
        Ok(n) => n,
        Err(_) => {
            unsafe { set_abi_errno(errno::EOVERFLOW) };
            -1
        }
    }
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
    let uses_positional = core_positional_printf_arg_plan(&segments).is_some();
    let mut arg_idx = 0usize;

    let read_arg = |position: Option<usize>, next_idx: &mut usize| -> Option<u64> {
        let idx = if let Some(position) = position {
            position.checked_sub(1)?
        } else {
            let current = *next_idx;
            *next_idx = (*next_idx).saturating_add(1);
            current
        };
        (idx < max_args).then(|| unsafe { *args.add(idx) })
    };

    for seg in &segments {
        match seg {
            FormatSegment::Literal(lit) => buf.extend_from_slice(lit),
            FormatSegment::Percent => buf.push(b'%'),
            FormatSegment::Spec(spec) => {
                // Resolve width from args if needed.
                let mut resolved_spec = spec.clone();
                if spec.width.uses_arg() {
                    let width_position = if uses_positional {
                        spec.width.position()
                    } else {
                        None
                    };
                    if let Some(raw_width) = read_arg(width_position, &mut arg_idx) {
                        let w = raw_width as i64;
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
                if spec.precision.uses_arg() {
                    let precision_position = if uses_positional {
                        spec.precision.position()
                    } else {
                        None
                    };
                    if let Some(raw_precision) = read_arg(precision_position, &mut arg_idx) {
                        let p = raw_precision as i64;
                        resolved_spec.precision = if p < 0 {
                            Precision::None
                        } else {
                            Precision::Fixed(p as usize)
                        };
                    } else {
                        resolved_spec.precision = Precision::None;
                    }
                }

                let value_position = if uses_positional {
                    spec.value_position
                } else {
                    None
                };

                if resolved_spec.is_literal_percent() {
                    buf.push(b'%');
                } else if resolved_spec.is_errno_message() {
                    let e = unsafe { *crate::errno_abi::__errno_location() };
                    let mut err_buf = [0u8; 256];
                    let rc = unsafe {
                        crate::string_abi::strerror_r(
                            e,
                            err_buf.as_mut_ptr() as *mut c_char,
                            err_buf.len(),
                        )
                    };
                    if rc == 0 {
                        let msg = unsafe { CStr::from_ptr(err_buf.as_ptr() as *const c_char) };
                        format_str(msg.to_bytes(), &resolved_spec, &mut buf);
                    } else {
                        buf.extend_from_slice(b"Unknown error");
                    }
                } else if resolved_spec.stores_count() {
                    // %n: store count of bytes written so far.
                    // Respects length modifier: %hhn→i8, %hn→i16,
                    // %n→i32, %ln→i64, %lln→i64, %zn→isize, %jn→i64.
                    if let Some(raw_ptr) = read_arg(value_position, &mut arg_idx) {
                        let ptr_val = raw_ptr as usize;
                        if ptr_val != 0 {
                            let count = buf.len();
                            let size = match resolved_spec.length {
                                LengthMod::Hh => 1,
                                LengthMod::H => 2,
                                LengthMod::L
                                | LengthMod::Ll
                                | LengthMod::J
                                | LengthMod::Z
                                | LengthMod::T => 8,
                                _ => 4,
                            };
                            let (mode, decision) = crate::runtime_policy::decide(
                                frankenlibc_membrane::runtime_math::ApiFamily::Stdio,
                                ptr_val,
                                size,
                                true,
                                false,
                                0,
                            );

                            let mut should_write = !matches!(
                                decision.action,
                                frankenlibc_membrane::runtime_math::MembraneAction::Deny
                            );
                            if mode.heals_enabled()
                                || matches!(
                                    decision.action,
                                    frankenlibc_membrane::runtime_math::MembraneAction::Repair(_)
                                )
                            {
                                // Only escalate to "skip the write" when we
                                // have POSITIVE evidence the allocation is
                                // too small. Absence of allocator tracking
                                // (`known_remaining` returns None for stack
                                // locals and external mallocs) is NOT
                                // evidence of danger — the membrane's
                                // decide() already ran; if its verdict was
                                // non-Deny we trust the caller's pointer.
                                // (bd-xx2j1: POSIX %n must write to the
                                // count slot even for untracked pointers.)
                                if let Some(rem) = crate::malloc_abi::known_remaining(ptr_val)
                                    && rem < size
                                {
                                    should_write = false;
                                    frankenlibc_membrane::heal::global_healing_policy().record(&frankenlibc_membrane::heal::HealingAction::ReturnSafeDefault);
                                }
                                // No `else` branch: untracked allocations
                                // are not evidence of danger. (bd-xx2j1)
                            }

                            if should_write {
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
                            crate::runtime_policy::observe(
                                frankenlibc_membrane::runtime_math::ApiFamily::Stdio,
                                decision.profile,
                                10,
                                !should_write,
                            );
                        }
                    }
                } else if resolved_spec.value_arg_is_string() {
                    if let Some(raw) = read_arg(value_position, &mut arg_idx) {
                        let ptr = raw as usize as *const u8;
                        if ptr.is_null() {
                            format_str(b"(null)", &resolved_spec, &mut buf);
                        } else {
                            let s_bytes = unsafe { c_str_bytes(ptr as *const c_char) };
                            format_str(s_bytes, &resolved_spec, &mut buf);
                        }
                    }
                } else if let Some(raw) = read_arg(value_position, &mut arg_idx) {
                    let _ = resolved_spec.render_value_arg(raw, &mut buf);
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
    let _trace_scope = runtime_policy::entrypoint_scope("snprintf");

    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        str_buf as usize,
        size,
        true,
        str_buf.is_null() && size > 0,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
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
    printf_result_to_c_int(total_len)
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
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut copy_len = total_len;
    let mut adverse = false;
    let mut has_room = true;

    if repair_enabled(mode.heals_enabled(), decision.action)
        && let Some(bound) = known_remaining(str_buf as usize)
    {
        if bound == 0 {
            has_room = false;
            adverse = true;
            global_healing_policy().record(&HealingAction::ClampSize {
                requested: total_len,
                clamped: 0,
            });
        } else {
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
    }

    if has_room {
        unsafe {
            std::ptr::copy_nonoverlapping(rendered.as_ptr(), str_buf as *mut u8, copy_len);
            *str_buf.add(copy_len) = 0;
        }
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        adverse,
    );
    printf_result_to_c_int(total_len)
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
    let id = canonical_stream_id(stream);

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        if s.is_mem_backed() {
            let written = s.mem_write(&rendered);
            if written > 0 {
                let start = s.offset().saturating_sub(written as i64);
                if start >= 0 {
                    unsafe { sync_fmemopen_write(id, start as usize, &rendered[..written]) };
                }
            }
            let adverse = written < total_len;
            if adverse {
                s.set_error();
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                adverse,
            );
            return if adverse {
                -1
            } else {
                printf_result_to_c_int(total_len)
            };
        }

        let write_result = match s.buffer_write(&rendered) {
            Some(result) => result,
            None => {
                runtime_policy::observe(
                    ApiFamily::Stdio,
                    decision.profile,
                    runtime_policy::scaled_cost(15, total_len),
                    true,
                );
                return -1;
            }
        };
        let flushed_from_buffer = write_result.flushed_from_buffer;
        if write_result.flush_needed {
            let fd = s.fd();
            let mut written = 0usize;
            let mut success = true;
            while written < write_result.flush_data.len() {
                let rc = unsafe {
                    sys_write_fd(
                        fd,
                        write_result.flush_data[written..].as_ptr().cast(),
                        write_result.flush_data.len() - written,
                    )
                };
                if rc <= 0 {
                    success = false;
                    break;
                }
                written += rc as usize;
            }
            if success {
                let flushed_new = write_result
                    .flush_data
                    .len()
                    .saturating_sub(flushed_from_buffer);
                let total_written = write_result.buffered.saturating_add(flushed_new);
                if total_written > 0 {
                    s.set_offset(s.offset().saturating_add(total_written as i64));
                }
            } else {
                s.set_error();
                s.mark_flushed();
                let flushed_new = written.saturating_sub(flushed_from_buffer);
                if flushed_new > 0 {
                    s.set_offset(s.offset().saturating_add(flushed_new as i64));
                }
                runtime_policy::observe(
                    ApiFamily::Stdio,
                    decision.profile,
                    runtime_policy::scaled_cost(15, total_len),
                    true,
                );
                return -1;
            }
        } else {
            let total_written = write_result.buffered;
            if total_written > 0 {
                s.set_offset(s.offset().saturating_add(total_written as i64));
            }
        }
    } else {
        drop(reg);
        // Not in our registry — delegate to host via fwrite on the rendered output.
        if let Some(host_fwrite) = unsafe { host_fwrite_fn() } {
            let written =
                unsafe { host_fwrite(rendered.as_ptr().cast(), 1, rendered.len(), stream) };
            if written > 0 {
                mark_host_io_started(stream);
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                written < rendered.len(),
            );
            return if written == rendered.len() {
                printf_result_to_c_int(total_len)
            } else {
                -1
            };
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        false,
    );
    printf_result_to_c_int(total_len)
}

/// POSIX `printf`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn printf(format: *const c_char, mut args: ...) -> c_int {
    if format.is_null() {
        return -1;
    }

    // POSIX: printf(...) is equivalent to fprintf(stdout, ...).
    // Route through the stdout stream to maintain buffer coherence.
    let stdout_ptr = active_stdout_stream();
    let id = canonical_stream_id(stdout_ptr);

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        if s.is_mem_backed() {
            let written = s.mem_write(&rendered);
            if written > 0 {
                let start = s.offset().saturating_sub(written as i64);
                if start >= 0 {
                    unsafe { sync_fmemopen_write(id, start as usize, &rendered[..written]) };
                }
            }
            let adverse = written < total_len;
            if adverse {
                s.set_error();
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                adverse,
            );
            return if adverse {
                -1
            } else {
                printf_result_to_c_int(total_len)
            };
        }

        let write_result = match s.buffer_write(&rendered) {
            Some(result) => result,
            None => {
                runtime_policy::observe(
                    ApiFamily::Stdio,
                    decision.profile,
                    runtime_policy::scaled_cost(15, total_len),
                    true,
                );
                return -1;
            }
        };
        let flushed_from_buffer = write_result.flushed_from_buffer;
        if write_result.flush_needed {
            let fd = s.fd();
            let mut written = 0usize;
            let mut success = true;
            while written < write_result.flush_data.len() {
                let rc = unsafe {
                    sys_write_fd(
                        fd,
                        write_result.flush_data[written..].as_ptr().cast(),
                        write_result.flush_data.len() - written,
                    )
                };
                if rc <= 0 {
                    success = false;
                    break;
                }
                written += rc as usize;
            }
            if !success {
                s.set_error();
                s.mark_flushed();
                let flushed_new = written.saturating_sub(flushed_from_buffer);
                if flushed_new > 0 {
                    s.set_offset(s.offset().saturating_add(flushed_new as i64));
                }
                runtime_policy::observe(
                    ApiFamily::Stdio,
                    decision.profile,
                    runtime_policy::scaled_cost(15, total_len),
                    true,
                );
                return -1;
            }
            let flushed_new = write_result
                .flush_data
                .len()
                .saturating_sub(flushed_from_buffer);
            let total_written = write_result.buffered.saturating_add(flushed_new);
            if total_written > 0 {
                s.set_offset(s.offset().saturating_add(total_written as i64));
            }
        } else {
            let total_written = write_result.buffered;
            if total_written > 0 {
                s.set_offset(s.offset().saturating_add(total_written as i64));
            }
        }
    } else {
        drop(reg);
        if let Some(host_fwrite) = unsafe { host_fwrite_fn() } {
            let written =
                unsafe { host_fwrite(rendered.as_ptr().cast(), 1, rendered.len(), stdout_ptr) };
            if written > 0 {
                mark_host_io_started(stdout_ptr);
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                written < rendered.len(),
            );
            return if written == rendered.len() {
                printf_result_to_c_int(total_len)
            } else {
                -1
            };
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        false,
    );
    printf_result_to_c_int(total_len)
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
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let adverse = !write_all_fd(fd, &rendered);
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        adverse,
    );
    if adverse {
        -1
    } else {
        printf_result_to_c_int(total_len)
    }
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
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
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
    printf_result_to_c_int(total_len)
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
    if let Some(plan) = core_positional_printf_arg_plan(segments) {
        for kind in plan.iter().take(extract_count) {
            match kind {
                ValueArgKind::Gp => {
                    if idx < extract_count {
                        buf[idx] =
                            unsafe { vprintf_read_gp(gp_offset_ptr, overflow_ptr, reg_save_ptr) };
                        idx += 1;
                    }
                }
                ValueArgKind::Fp => {
                    if idx < extract_count {
                        buf[idx] =
                            unsafe { vprintf_read_fp(fp_offset_ptr, overflow_ptr, reg_save_ptr) };
                        idx += 1;
                    }
                }
            }
        }
    } else {
        for seg in segments {
            if let FormatSegment::Spec(spec) = seg {
                if spec.width.uses_arg() && idx < extract_count {
                    buf[idx] =
                        unsafe { vprintf_read_gp(gp_offset_ptr, overflow_ptr, reg_save_ptr) };
                    idx += 1;
                }
                if spec.precision.uses_arg() && idx < extract_count {
                    buf[idx] =
                        unsafe { vprintf_read_gp(gp_offset_ptr, overflow_ptr, reg_save_ptr) };
                    idx += 1;
                }
                if spec.value_arg_is_float() && idx < extract_count {
                    buf[idx] =
                        unsafe { vprintf_read_fp(fp_offset_ptr, overflow_ptr, reg_save_ptr) };
                    idx += 1;
                } else if spec.value_arg_is_gp() && idx < extract_count {
                    buf[idx] =
                        unsafe { vprintf_read_gp(gp_offset_ptr, overflow_ptr, reg_save_ptr) };
                    idx += 1;
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
    let needed = core_count_printf_args(&segments);
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
    let _trace_scope = runtime_policy::entrypoint_scope("vsnprintf");
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Stdio, str_buf as usize, size, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
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
    printf_result_to_c_int(total_len)
}

#[doc(hidden)]
pub fn signal_runtime_ready_for_tests() {
    runtime_policy::signal_runtime_ready();
}

#[doc(hidden)]
pub fn take_last_decision_gate_for_tests() -> Option<&'static str> {
    runtime_policy::take_last_explainability().map(|explain| explain.decision_gate)
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
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    unsafe { vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut copy_len = total_len;
    let mut adverse = false;
    let mut has_room = true;

    if repair_enabled(mode.heals_enabled(), decision.action)
        && let Some(bound) = known_remaining(str_buf as usize)
    {
        if bound == 0 {
            has_room = false;
            adverse = true;
            global_healing_policy().record(&HealingAction::ClampSize {
                requested: total_len,
                clamped: 0,
            });
        } else {
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
    }

    if has_room {
        unsafe {
            std::ptr::copy_nonoverlapping(rendered.as_ptr(), str_buf as *mut u8, copy_len);
            *str_buf.add(copy_len) = 0;
        }
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        adverse,
    );
    printf_result_to_c_int(total_len)
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
    let id = canonical_stream_id(stream);
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    unsafe { vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        if s.is_mem_backed() {
            let written = s.mem_write(&rendered);
            if written > 0 {
                let start = s.offset().saturating_sub(written as i64);
                if start >= 0 {
                    unsafe { sync_fmemopen_write(id, start as usize, &rendered[..written]) };
                }
            }
            let adverse = written < total_len;
            if adverse {
                s.set_error();
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                adverse,
            );
            return if adverse {
                -1
            } else {
                printf_result_to_c_int(total_len)
            };
        }

        let write_result = match s.buffer_write(&rendered) {
            Some(result) => result,
            None => {
                runtime_policy::observe(
                    ApiFamily::Stdio,
                    decision.profile,
                    runtime_policy::scaled_cost(15, total_len),
                    true,
                );
                return -1;
            }
        };
        let flushed_from_buffer = write_result.flushed_from_buffer;
        if write_result.flush_needed {
            let fd = s.fd();
            let mut written = 0usize;
            let mut success = true;
            while written < write_result.flush_data.len() {
                let rc = unsafe {
                    sys_write_fd(
                        fd,
                        write_result.flush_data[written..].as_ptr().cast(),
                        write_result.flush_data.len() - written,
                    )
                };
                if rc <= 0 {
                    success = false;
                    break;
                }
                written += rc as usize;
            }
            if !success {
                s.set_error();
                s.mark_flushed();
                let flushed_new = written.saturating_sub(flushed_from_buffer);
                if flushed_new > 0 {
                    s.set_offset(s.offset().saturating_add(flushed_new as i64));
                }
                runtime_policy::observe(
                    ApiFamily::Stdio,
                    decision.profile,
                    runtime_policy::scaled_cost(15, total_len),
                    true,
                );
                return -1;
            }
            let flushed_new = write_result
                .flush_data
                .len()
                .saturating_sub(flushed_from_buffer);
            let total_written = write_result.buffered.saturating_add(flushed_new);
            if total_written > 0 {
                s.set_offset(s.offset().saturating_add(total_written as i64));
            }
        } else {
            let total_written = write_result.buffered;
            if total_written > 0 {
                s.set_offset(s.offset().saturating_add(total_written as i64));
            }
        }
    } else {
        drop(reg);
        // Not in our registry — delegate to host via fwrite on the rendered output.
        if let Some(host_fwrite) = unsafe { host_fwrite_fn() } {
            let written =
                unsafe { host_fwrite(rendered.as_ptr().cast(), 1, rendered.len(), stream) };
            if written > 0 {
                mark_host_io_started(stream);
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                written < rendered.len(),
            );
            return if written == rendered.len() {
                printf_result_to_c_int(total_len)
            } else {
                -1
            };
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        false,
    );
    printf_result_to_c_int(total_len)
}

/// POSIX `vprintf` — format to stdout from va_list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vprintf(format: *const c_char, ap: *mut c_void) -> c_int {
    if format.is_null() {
        return -1;
    }

    let stdout_ptr = active_stdout_stream();
    let id = canonical_stream_id(stdout_ptr);
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };
    let segments = parse_format_string(fmt_bytes);
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    unsafe { vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let rendered = unsafe { render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    let total_len = rendered.len();

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        if s.is_mem_backed() {
            let written = s.mem_write(&rendered);
            if written > 0 {
                let start = s.offset().saturating_sub(written as i64);
                if start >= 0 {
                    unsafe { sync_fmemopen_write(id, start as usize, &rendered[..written]) };
                }
            }
            let adverse = written < total_len;
            if adverse {
                s.set_error();
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                adverse,
            );
            return if adverse {
                -1
            } else {
                printf_result_to_c_int(total_len)
            };
        }

        let write_result = match s.buffer_write(&rendered) {
            Some(result) => result,
            None => {
                runtime_policy::observe(
                    ApiFamily::Stdio,
                    decision.profile,
                    runtime_policy::scaled_cost(15, total_len),
                    true,
                );
                return -1;
            }
        };
        let flushed_from_buffer = write_result.flushed_from_buffer;
        if write_result.flush_needed {
            let fd = s.fd();
            let mut written = 0usize;
            let mut success = true;
            while written < write_result.flush_data.len() {
                let rc = unsafe {
                    sys_write_fd(
                        fd,
                        write_result.flush_data[written..].as_ptr().cast(),
                        write_result.flush_data.len() - written,
                    )
                };
                if rc <= 0 {
                    success = false;
                    break;
                }
                written += rc as usize;
            }
            if !success {
                s.set_error();
                s.mark_flushed();
                let flushed_new = written.saturating_sub(flushed_from_buffer);
                if flushed_new > 0 {
                    s.set_offset(s.offset().saturating_add(flushed_new as i64));
                }
                runtime_policy::observe(
                    ApiFamily::Stdio,
                    decision.profile,
                    runtime_policy::scaled_cost(15, total_len),
                    true,
                );
                return -1;
            }
            let flushed_new = write_result
                .flush_data
                .len()
                .saturating_sub(flushed_from_buffer);
            let total_written = write_result.buffered.saturating_add(flushed_new);
            if total_written > 0 {
                s.set_offset(s.offset().saturating_add(total_written as i64));
            }
        } else {
            let total_written = write_result.buffered;
            if total_written > 0 {
                s.set_offset(s.offset().saturating_add(total_written as i64));
            }
        }
    } else {
        drop(reg);
        if let Some(host_fwrite) = unsafe { host_fwrite_fn() } {
            let written =
                unsafe { host_fwrite(rendered.as_ptr().cast(), 1, rendered.len(), stdout_ptr) };
            if written > 0 {
                mark_host_io_started(stdout_ptr);
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                written < rendered.len(),
            );
            return if written == rendered.len() {
                printf_result_to_c_int(total_len)
            } else {
                -1
            };
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        false,
    );
    printf_result_to_c_int(total_len)
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
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
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
    if adverse {
        -1
    } else {
        printf_result_to_c_int(total_len)
    }
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
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
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
    printf_result_to_c_int(total_len)
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
    let id = canonical_stream_id(stream);
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
    let id = canonical_stream_id(stream);
    if !registry_contains_stream(id)
        && let Some(host_vfscanf) = unsafe { host_vfscanf_fn() }
    {
        let rc = unsafe { host_vfscanf(stream, format, ap) };
        mark_host_io_started(stream);
        if rc < 0 {
            unsafe { sync_host_errno(0) };
        }
        return rc;
    }
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

// __printf_chk — defined in fortify_abi.rs (canonical module)

// __fprintf_chk — defined in fortify_abi.rs (canonical module)

// __sprintf_chk — defined in fortify_abi.rs (canonical module)

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

    let id = canonical_stream_id(stream);
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return -1;
    }

    if !registry_contains_stream(id)
        && let Some(host_fgetpos) = unsafe { host_fgetpos_fn() }
    {
        let rc = unsafe { host_fgetpos(stream, pos) };
        if rc != 0 {
            unsafe { sync_host_errno(errno::EINVAL) };
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, rc != 0);
        return rc;
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

    let id = canonical_stream_id(stream);
    if !registry_contains_stream(id)
        && let Some(host_fsetpos) = unsafe { host_fsetpos_fn() }
    {
        let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
        if matches!(decision.action, MembraneAction::Deny) {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
            return -1;
        }
        let rc = unsafe { host_fsetpos(stream, pos) };
        if rc != 0 {
            unsafe { sync_host_errno(errno::EINVAL) };
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, rc != 0);
        return rc;
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
/// Returns an opaque stream handle managed by the ABI registry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdopen(fd: c_int, mode: *const c_char) -> *mut c_void {
    if mode.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }
    if fd < 0 {
        unsafe { set_abi_errno(errno::EBADF) };
        return std::ptr::null_mut();
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, fd as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    // Parse mode string into open flags.
    let mode_bytes = unsafe { CStr::from_ptr(mode) }.to_bytes();
    let Some(open_flags) = parse_mode(mode_bytes) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return std::ptr::null_mut();
    };

    if open_flags.cloexec {
        let existing = match unsafe { raw_syscall::sys_fcntl(fd, libc::F_GETFD, 0) } {
            Ok(flags) => flags,
            Err(e) => {
                unsafe { set_abi_errno(e) };
                runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
                return std::ptr::null_mut();
            }
        };
        let _ = unsafe {
            raw_syscall::sys_fcntl(fd, libc::F_SETFD, (existing | libc::FD_CLOEXEC) as usize)
        };
    }

    // Create stream via fdopen_native_impl.
    let fp = fdopen_native_impl(fd, &open_flags);
    if fp.is_null() {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
    } else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, false);
    }
    fp
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

    let id = canonical_stream_id(stream);
    let (safety_mode, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return std::ptr::null_mut();
    }

    let repair = repair_enabled(safety_mode.heals_enabled(), decision.action);

    // Validate pathname if provided.
    if !pathname.is_null() {
        let (_path_len, path_terminated) = unsafe {
            scan_c_str_len(
                pathname,
                if repair {
                    known_remaining(pathname as usize)
                } else {
                    None
                },
            )
        };
        if !path_terminated && repair {
            unsafe { set_abi_errno(errno::ENAMETOOLONG) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
            return std::ptr::null_mut();
        }
    }

    // Validate mode string.
    let (mode_len, mode_terminated) = unsafe {
        scan_c_str_len(
            mode,
            if repair {
                known_remaining(mode as usize)
            } else {
                None
            },
        )
    };
    if !mode_terminated {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    let mode_bytes = unsafe { std::slice::from_raw_parts(mode as *const u8, mode_len) };
    let Some(open_flags) = parse_mode(mode_bytes) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return std::ptr::null_mut();
    };

    if !registry_contains_stream(id)
        && let Some(host_freopen) = unsafe { host_freopen_fn() }
    {
        unregister_host_stream(stream);
        let result = unsafe { host_freopen(pathname, mode, stream) };
        if result.is_null() {
            unsafe { sync_host_errno(errno::EINVAL) };
        } else {
            register_host_stream(result);
        }
        return result;
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());

    // Close the old stream.
    let mut target_fd = -1;
    if let Some(mut old) = reg.streams.remove(&id) {
        if old.is_mem_backed() {
            unsafe {
                sync_memstream_to_caller(id, &old);
                sync_fmemopen_full(id, &old);
                crate::wchar_abi::sync_open_wmemstream_to_caller(id, &old);
            }
            let mut sync_guard = mem_sync_registry()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(ref mut map) = *sync_guard {
                map.remove(&id);
            }
            let mut fixed_guard = mem_fixed_registry()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(ref mut map) = *fixed_guard {
                map.remove(&id);
            }
            crate::wchar_abi::unregister_open_wmemstream(id);
        }
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
            let _ = raw_syscall::sys_close(old_fd);
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
    let mut fd = match unsafe {
        raw_syscall::sys_openat(libc::AT_FDCWD, pathname as *const u8, oflags, create_mode)
    } {
        Ok(f) => f,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 30, true);
            return std::ptr::null_mut();
        }
    };

    // If reopening a standard stream, dup2 the new fd onto the standard fd.
    if target_fd >= 0 && fd != target_fd {
        let _ = raw_syscall::sys_dup2(fd, target_fd);
        let _ = raw_syscall::sys_close(fd);
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
    if let Ok(()) = unsafe { raw_syscall::sys_unlinkat(libc::AT_FDCWD, pathname as *const u8, 0) } {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, false);
        return 0;
    }

    // Check if it's a directory.
    let errno_val = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(errno::EIO);
    if errno_val == errno::EISDIR
        && let Ok(()) = unsafe {
            raw_syscall::sys_unlinkat(libc::AT_FDCWD, pathname as *const u8, libc::AT_REMOVEDIR)
        }
    {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, false);
        return 0;
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

    let id = canonical_stream_id(stream);
    if !registry_contains_stream(id)
        && let Some(host_getdelim) = unsafe { host_getdelim_fn() }
    {
        let rc = unsafe { host_getdelim(lineptr, n, delim, stream) };
        if rc < 0 {
            unsafe { sync_host_errno(0) };
        } else {
            mark_host_io_started(stream);
        }
        return rc;
    }
    let id = canonical_stream_id(stream);
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
        let new_buf = if let Some(host_realloc) = crate::host_resolve::host_realloc_raw() {
            unsafe { host_realloc(current_buf.cast(), new_size) }
        } else {
            unsafe { crate::malloc_abi::realloc(current_buf.cast(), new_size) }
        };
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
    if lineptr.is_null() || n.is_null() || stream.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let id = canonical_stream_id(stream);
    if !registry_contains_stream(id)
        && let Some(host_getline) = unsafe { host_getline_fn() }
    {
        let rc = unsafe { host_getline(lineptr, n, stream) };
        if rc < 0 {
            unsafe { sync_host_errno(0) };
        } else {
            mark_host_io_started(stream);
        }
        return rc;
    }
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
        raw_syscall::sys_openat(
            libc::AT_FDCWD,
            c"/tmp".as_ptr() as *const u8,
            libc::O_RDWR | libc::O_TMPFILE | libc::O_EXCL,
            0o600,
        )
    }
    .unwrap_or(-1);

    if fd < 0 {
        // Fallback: create a named temp file and unlink it.
        let template = b"/tmp/frankenlibc_XXXXXX\0";
        let mut path = *template;
        let fd2 = unsafe { crate::wchar_abi::mkstemp(path.as_mut_ptr().cast()) };
        if fd2 < 0 {
            let e = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(errno::EIO);
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 20, true);
            return std::ptr::null_mut();
        }
        // Unlink immediately so it's deleted on close.
        let _ = unsafe { raw_syscall::sys_unlinkat(libc::AT_FDCWD, path.as_ptr(), 0) };

        let open_flags = OpenFlags {
            readable: true,
            writable: true,
            ..Default::default()
        };
        let fp = fdopen_native_impl(fd2, &open_flags);
        if fp.is_null() {
            let _ = raw_syscall::sys_close(fd2);
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 20, true);
            return std::ptr::null_mut();
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 20, false);
        return fp;
    }

    let open_flags = OpenFlags {
        readable: true,
        writable: true,
        ..Default::default()
    };
    let fp = fdopen_native_impl(fd, &open_flags);
    if fp.is_null() {
        let _ = raw_syscall::sys_close(fd);
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 20, true);
        return std::ptr::null_mut();
    }

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 20, false);
    fp
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
    let pid = raw_syscall::sys_getpid() as u32;

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

    let mode_bytes = unsafe { std::ffi::CStr::from_ptr(typ) }.to_bytes();
    if mode_bytes.is_empty() {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
        return std::ptr::null_mut();
    }
    let mode = mode_bytes[0];
    let reading = mode == b'r';
    if mode != b'r' && mode != b'w' {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
        return std::ptr::null_mut();
    }
    let mut close_on_exec = false;
    for &flag in &mode_bytes[1..] {
        if flag == b'e' && !close_on_exec {
            close_on_exec = true;
        } else {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
            return std::ptr::null_mut();
        }
    }

    // Create pipe: pipe_fds[0] = read end, pipe_fds[1] = write end.
    let mut pipe_fds = [0i32; 2];
    let pipe_flags = if close_on_exec { libc::O_CLOEXEC } else { 0 };
    let pipe_result = unsafe { raw_syscall::sys_pipe2(pipe_fds.as_mut_ptr(), pipe_flags) };
    if let Err(e) = pipe_result {
        if e != libc::ENOSYS {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
            return std::ptr::null_mut();
        }
        // Fallback for kernels without pipe2: use pipe2(0) + fcntl(FD_CLOEXEC) if requested.
        if let Err(e) = unsafe { raw_syscall::sys_pipe2(pipe_fds.as_mut_ptr(), 0) } {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
            return std::ptr::null_mut();
        }
        if close_on_exec {
            if let Err(e) = unsafe {
                raw_syscall::sys_fcntl(pipe_fds[0], libc::F_SETFD, libc::FD_CLOEXEC as usize)
            } {
                let _ = raw_syscall::sys_close(pipe_fds[0]);
                let _ = raw_syscall::sys_close(pipe_fds[1]);
                unsafe { set_abi_errno(e) };
                runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
                return std::ptr::null_mut();
            }
            if let Err(e) = unsafe {
                raw_syscall::sys_fcntl(pipe_fds[1], libc::F_SETFD, libc::FD_CLOEXEC as usize)
            } {
                let _ = raw_syscall::sys_close(pipe_fds[0]);
                let _ = raw_syscall::sys_close(pipe_fds[1]);
                unsafe { set_abi_errno(e) };
                runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
                return std::ptr::null_mut();
            }
        }
    }

    // Fork via clone(SIGCHLD).
    let pid = match raw_syscall::sys_clone_fork(libc::SIGCHLD as usize) {
        Ok(p) => p,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            let _ = raw_syscall::sys_close(pipe_fds[0]);
            let _ = raw_syscall::sys_close(pipe_fds[1]);
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
            return std::ptr::null_mut();
        }
    };

    if pid == 0 {
        // Child process.
        let child_exit = || -> ! { raw_syscall::sys_exit_group(127) };

        if reading {
            // Parent reads from child's stdout: dup write end to stdout.
            if raw_syscall::sys_close(pipe_fds[0]).is_err() {
                child_exit();
            }
            if raw_syscall::sys_dup2(pipe_fds[1], libc::STDOUT_FILENO).is_err() {
                child_exit();
            }
            if raw_syscall::sys_close(pipe_fds[1]).is_err() {
                child_exit();
            }
        } else {
            // Parent writes to child's stdin: dup read end to stdin.
            if raw_syscall::sys_close(pipe_fds[1]).is_err() {
                child_exit();
            }
            if raw_syscall::sys_dup2(pipe_fds[0], libc::STDIN_FILENO).is_err() {
                child_exit();
            }
            if raw_syscall::sys_close(pipe_fds[0]).is_err() {
                child_exit();
            }
        }

        let sh = c"/bin/sh".as_ptr();
        let dash_c = c"-c".as_ptr();
        let argv: [*const c_char; 4] = [sh, dash_c, command, std::ptr::null()];
        // Pass the current process environment so the child inherits PATH, etc.
        unsafe extern "C" {
            static mut environ: *mut *mut c_char;
        }
        let _ = unsafe {
            raw_syscall::sys_execve(
                sh as *const u8,
                argv.as_ptr() as *const *const u8,
                environ as *const *const u8,
            )
        };
        child_exit();
    }

    // Parent: close unused end and wrap the other in a stdio stream.
    let our_fd = if reading {
        let _ = raw_syscall::sys_close(pipe_fds[1]);
        pipe_fds[0]
    } else {
        let _ = raw_syscall::sys_close(pipe_fds[0]);
        pipe_fds[1]
    };

    let open_flags = OpenFlags {
        readable: reading,
        writable: !reading,
        cloexec: close_on_exec,
        ..Default::default()
    };

    // Create stream via fdopen_native_impl.
    let fp = fdopen_native_impl(our_fd, &open_flags);
    if fp.is_null() {
        // fdopen failed (registry full) - close fd and waitpid to reap child.
        let _ = raw_syscall::sys_close(our_fd);
        unsafe { crate::process_abi::waitpid(pid, std::ptr::null_mut(), 0) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
        return std::ptr::null_mut();
    }

    let id = canonical_stream_id(fp);
    {
        let mut guard = POPEN_PIDS.lock().unwrap_or_else(|e| e.into_inner());
        let map = guard.get_or_insert_with(HashMap::new);
        map.insert(id, pid);
    }

    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, false);
    fp
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

    let id = canonical_stream_id(stream);
    let pid = {
        let mut pids = POPEN_PIDS.lock().unwrap_or_else(|e| e.into_inner());
        pids.as_mut().and_then(|m| m.remove(&id))
    };
    let Some(pid) = pid else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    };

    // Close the stream (flushes and closes fd).
    unsafe { fclose(stream) };

    // Wait for child.
    let mut wstatus: c_int = 0;
    loop {
        match unsafe { raw_syscall::sys_wait4(pid, &mut wstatus, 0, std::ptr::null_mut()) } {
            Ok(child_pid) if child_pid == pid => break,
            Ok(_) => continue,
            Err(libc::EINTR) => continue,
            Err(e) => {
                unsafe { set_abi_errno(e) };
                return -1;
            }
        }
    }

    wstatus
}

// __snprintf_chk — defined in fortify_abi.rs (canonical module)

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

/// Metadata for fmemopen with a caller-provided fixed buffer.
struct MemFixedSync {
    buf: *mut u8,
    size: usize,
}

// SAFETY: MemFixedSync holds raw pointers provided by the caller.
// The caller must keep the buffer valid for the lifetime of the stream.
unsafe impl Send for MemFixedSync {}
unsafe impl Sync for MemFixedSync {}

/// Registry of fmemopen fixed-buffer metadata, keyed by stream sentinel ID.
static MEM_FIXED_SYNC: Mutex<Option<HashMap<usize, MemFixedSync>>> = Mutex::new(None);

fn mem_fixed_registry() -> &'static Mutex<Option<HashMap<usize, MemFixedSync>>> {
    &MEM_FIXED_SYNC
}

/// Synchronize newly written bytes for fmemopen fixed buffers.
unsafe fn sync_fmemopen_write(id: usize, start: usize, src: &[u8]) {
    let guard = mem_fixed_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(ref map) = *guard
        && let Some(info) = map.get(&id)
        && start < info.size
    {
        let max = info.size - start;
        let len = src.len().min(max);
        if len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(src.as_ptr(), info.buf.add(start), len);
            }
        }
    }
}

/// Synchronize the full fmemopen fixed buffer contents to the caller.
unsafe fn sync_fmemopen_full(id: usize, stream: &StdioStream) {
    let guard = mem_fixed_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(ref map) = *guard
        && let Some(info) = map.get(&id)
        && let Some(data) = stream.mem_data()
    {
        let len = data.len().min(info.size);
        if len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), info.buf, len);
            }
        }
    }
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
        let previous = unsafe { *info.ptr_loc };
        // Allocate a new buffer via malloc and copy data + NUL terminator.
        let buf = unsafe { malloc(len + 1) };
        if !buf.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), buf.cast::<u8>(), len);
                *buf.cast::<u8>().add(len) = 0; // NUL-terminate
                *info.ptr_loc = buf.cast::<c_char>();
                *info.size_loc = len;
                if !previous.is_null() {
                    free(previous.cast::<c_void>());
                }
            }
        }
    }
    drop(sync_guard);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setlinebuf(stream: *mut c_void) {
    let _ = unsafe { setvbuf(stream, std::ptr::null_mut(), 1, 0) };
}

/// Classify stream type for locking purposes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamType {
    /// Native NativeFile stream (stdin/stdout/stderr) - has ReentrantMutex locking
    NativeFile(usize), // slot index
    /// Legacy StdioStream from our registry - no mutex support, locking is no-op
    LegacyStdioStream,
    /// Foreign stream from host glibc - delegate to host locking functions
    Foreign,
}

/// Classify a stream pointer for locking purposes.
///
/// Uses bloom filter pre-check (~10ns) for fast ownership detection.
fn classify_stream_for_locking(stream: *mut c_void) -> StreamType {
    if stream.is_null() {
        return StreamType::Foreign;
    }

    // Check for sentinels first (these are well-known addresses, not in bloom)
    match stream as usize {
        STDIN_SENTINEL => return StreamType::NativeFile(0),
        STDOUT_SENTINEL => return StreamType::NativeFile(1),
        STDERR_SENTINEL => return StreamType::NativeFile(2),
        _ => {}
    }

    // Fast path: bloom filter pre-check (~10ns)
    // If bloom says "definitely not ours", skip expensive lookups
    if io_internal_abi::might_be_native_file(stream) {
        // Bloom says "might be ours" - verify via registry lookup
        if let Some(slot) = io_internal_abi::verify_native_file(stream) {
            return StreamType::NativeFile(slot);
        }
    }

    // Check if registered in our legacy StdioStream registry
    let id = canonical_stream_id(stream);
    if registry_contains_stream(id) {
        // This is our stream (from fopen, etc.) but using legacy StdioStream
        // which doesn't have mutex support. Treat as no-op for locking.
        return StreamType::LegacyStdioStream;
    }

    // Not our stream - foreign glibc stream
    StreamType::Foreign
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn flockfile(stream: *mut c_void) {
    if stream.is_null() {
        return;
    }
    match classify_stream_for_locking(stream) {
        StreamType::NativeFile(slot) => {
            let reg = io_internal_abi::native_stream_registry();
            if let Some(native_file) = reg.get(slot) {
                native_file.explicit_lock();
            }
        }
        StreamType::LegacyStdioStream => {
            // Legacy StdioStream doesn't have mutex support.
            // Per bd-9chy.17: locking for these is a no-op until fully migrated to NativeFile.
        }
        StreamType::Foreign => {
            if let Some(host_flockfile) = unsafe { host_flockfile_fn() } {
                unsafe { host_flockfile(stream) };
            }
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftrylockfile(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        return -1;
    }
    match classify_stream_for_locking(stream) {
        StreamType::NativeFile(slot) => {
            let reg = io_internal_abi::native_stream_registry();
            if let Some(native_file) = reg.get(slot) {
                return if native_file.try_explicit_lock() {
                    0
                } else {
                    -1
                };
            }
            0 // Slot not found - treat as success
        }
        StreamType::LegacyStdioStream => {
            // Legacy StdioStream: always succeeds (no actual lock)
            0
        }
        StreamType::Foreign => {
            if let Some(host_ftrylockfile) = unsafe { host_ftrylockfile_fn() } {
                return unsafe { host_ftrylockfile(stream) };
            }
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn funlockfile(stream: *mut c_void) {
    if stream.is_null() {
        return;
    }
    match classify_stream_for_locking(stream) {
        StreamType::NativeFile(slot) => {
            let reg = io_internal_abi::native_stream_registry();
            if let Some(native_file) = reg.get(slot) {
                // SAFETY: Caller is responsible for having called flockfile/ftrylockfile first.
                // This is the POSIX contract - funlockfile behavior is undefined if the caller
                // doesn't hold the lock.
                unsafe { native_file.explicit_unlock() };
            }
        }
        StreamType::LegacyStdioStream => {
            // Legacy StdioStream: no-op
        }
        StreamType::Foreign => {
            if let Some(host_funlockfile) = unsafe { host_funlockfile_fn() } {
                unsafe { host_funlockfile(stream) };
            }
        }
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
        // For truncate modes ("w"/"w+"), content starts empty.
        // For append modes, content_len = first NUL byte or size.
        // For read-only and read/write (non-truncate) modes, content_len = size.
        let slice = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), size) };
        let mut v = vec![0u8; size];
        if !open_flags.truncate {
            v[..size].copy_from_slice(slice);
        }

        let cl = if open_flags.truncate {
            0
        } else if open_flags.append {
            v.iter().position(|&b| b == 0).unwrap_or(size)
        } else if open_flags.readable && !open_flags.writable {
            size
        } else if open_flags.writable && !open_flags.readable {
            0
        } else {
            size
        };
        (v, cl)
    };

    let stream = StdioStream::new_mem_fixed(data, content_len, open_flags);
    let handle = register_memory_stream_with_native_handle(
        stream,
        io_internal_abi::NativeFileBacking::MemoryFixed {
            buf: buf.cast::<u8>(),
            size,
            content_len,
            owns: buf.is_null(),
        },
        open_flags,
    );
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let id = canonical_stream_id(handle);

    if !buf.is_null() {
        let mut guard = mem_fixed_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let map = guard.get_or_insert_with(HashMap::new);
        map.insert(
            id,
            MemFixedSync {
                buf: buf.cast::<u8>(),
                size,
            },
        );
        if open_flags.truncate {
            unsafe {
                std::ptr::write_bytes(buf.cast::<u8>(), 0, size);
            }
        }
    }

    handle
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

    let initial_buf = unsafe { malloc(1) };
    if initial_buf.is_null() {
        unsafe { set_abi_errno(errno::ENOMEM) };
        return std::ptr::null_mut();
    }

    let stream = StdioStream::new_mem_dynamic();
    let handle = register_memory_stream_with_native_handle(
        stream,
        io_internal_abi::NativeFileBacking::MemoryGrowing {
            buf_ptr: ptr,
            size_ptr: sizeloc,
            capacity: 1,
            data: Vec::new(),
        },
        OpenFlags {
            writable: true,
            ..Default::default()
        },
    );
    if handle.is_null() {
        unsafe { free(initial_buf.cast::<c_void>()) };
        return std::ptr::null_mut();
    }
    let id = canonical_stream_id(handle);

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
        *initial_buf.cast::<u8>() = 0; // NUL-terminate
        *ptr = initial_buf.cast::<c_char>();
        *sizeloc = 0;
    }

    handle
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

    let len = unsafe { crate::string_abi::strlen(template) };
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

// ===========================================================================
// Unlocked stdio variants — bypass locking, delegate to locked versions
// ===========================================================================

/// `getchar_unlocked` — read a character from stdin without locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getchar_unlocked() -> c_int {
    unsafe { getchar() }
}

/// `putchar_unlocked` — write a character to stdout without locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putchar_unlocked(c: c_int) -> c_int {
    unsafe { putchar(c) }
}

/// `fread_unlocked` — binary stream input without locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fread_unlocked(
    ptr: *mut c_void,
    size: usize,
    nmemb: usize,
    stream: *mut c_void,
) -> usize {
    unsafe { fread(ptr, size, nmemb, stream) }
}

/// `fwrite_unlocked` — binary stream output without locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fwrite_unlocked(
    ptr: *const c_void,
    size: usize,
    nmemb: usize,
    stream: *mut c_void,
) -> usize {
    unsafe { fwrite(ptr, size, nmemb, stream) }
}

/// `fgets_unlocked` — get a string from stream without locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgets_unlocked(
    buf: *mut c_char,
    size: c_int,
    stream: *mut c_void,
) -> *mut c_char {
    unsafe { fgets(buf, size, stream) }
}

/// `fputs_unlocked` — put a string to stream without locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fputs_unlocked(s: *const c_char, stream: *mut c_void) -> c_int {
    unsafe { fputs(s, stream) }
}

/// `clearerr_unlocked` — clear stream error/EOF indicators without locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clearerr_unlocked(stream: *mut c_void) {
    unsafe { clearerr(stream) }
}

/// `fileno_unlocked` — get file descriptor from stream without locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fileno_unlocked(stream: *mut c_void) -> c_int {
    unsafe { fileno(stream) }
}

/// `setbuffer` — set buffering for a stream (BSD extension).
/// Equivalent to `setvbuf(stream, buf, buf ? _IOFBF : _IONBF, BUFSIZ)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setbuffer(stream: *mut c_void, buf: *mut c_char, size: usize) {
    if stream.is_null() {
        return;
    }
    let mode = if buf.is_null() {
        2 // _IONBF
    } else {
        0 // _IOFBF
    };
    unsafe { setvbuf(stream, buf, mode, size) };
}

// ===========================================================================
// __isoc99_* scanf aliases — GCC/clang emit these for C99+ code
// ===========================================================================

/// `__isoc99_scanf` — C99-conformant scanf (alias for scanf).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_scanf(format: *const c_char, mut args: ...) -> c_int {
    let ap = std::ptr::addr_of_mut!(args).cast::<c_void>();
    unsafe { vscanf(format, ap) }
}

/// `__isoc99_sscanf` — C99-conformant sscanf (alias for sscanf).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_sscanf(
    s: *const c_char,
    format: *const c_char,
    mut args: ...
) -> c_int {
    let ap = std::ptr::addr_of_mut!(args).cast::<c_void>();
    unsafe { vsscanf(s, format, ap) }
}

/// `__isoc99_fscanf` — C99-conformant fscanf (alias for fscanf).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_fscanf(
    stream: *mut c_void,
    format: *const c_char,
    mut args: ...
) -> c_int {
    let ap = std::ptr::addr_of_mut!(args).cast::<c_void>();
    unsafe { vfscanf(stream, format, ap) }
}

/// `__isoc99_vscanf` — C99-conformant vscanf (alias for vscanf).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_vscanf(format: *const c_char, ap: *mut c_void) -> c_int {
    unsafe { vscanf(format, ap) }
}

/// `__isoc99_vsscanf` — C99-conformant vsscanf (alias for vsscanf).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_vsscanf(
    s: *const c_char,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { vsscanf(s, format, ap) }
}

/// `__isoc99_vfscanf` — C99-conformant vfscanf (alias for vfscanf).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isoc99_vfscanf(
    stream: *mut c_void,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { vfscanf(stream, format, ap) }
}

// ===========================================================================
// getw / putw — legacy SVID/POSIX.1 word I/O
// ===========================================================================

/// `getw` — read an int from a stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getw(stream: *mut c_void) -> c_int {
    let mut val: c_int = 0;
    let n = unsafe {
        fread(
            &mut val as *mut c_int as *mut c_void,
            std::mem::size_of::<c_int>(),
            1,
            stream,
        )
    };
    if n != 1 { libc::EOF } else { val }
}

/// `putw` — write an int to a stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putw(w: c_int, stream: *mut c_void) -> c_int {
    let n = unsafe {
        fwrite(
            &w as *const c_int as *const c_void,
            std::mem::size_of::<c_int>(),
            1,
            stream,
        )
    };
    if n != 1 { libc::EOF } else { 0 }
}

// ── C23 __isoc23_* scanf aliases ─────────────────────────────────────────────
//
// GCC 14+ with -std=c23 emits __isoc23_* variants for scanf family functions.
// These are ABI-identical to the base versions.
// ── glibc _IO_* internal libio symbols ──────────────────────────────────────
//
// Many programs compiled against glibc link to these internal libio symbols
// directly (e.g., _IO_putc, _IO_getc). They are thin wrappers over the
// standard stdio functions.
#[allow(non_snake_case, non_upper_case_globals)]
mod _io_internal {
    use super::*;

    // NOTE: _IO_putc and _IO_getc are defined in io_internal_abi.rs
    // (the canonical location for _IO_* internal symbols).

    /// `_IO_puts` — glibc internal puts.
    #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
    pub unsafe extern "C" fn _IO_puts(s: *const c_char) -> c_int {
        unsafe { puts(s) }
    }

    // NOTE: _IO_feof and _IO_ferror are defined in io_internal_abi.rs.

    /// `_IO_flockfile` — glibc internal flockfile.
    #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
    pub unsafe extern "C" fn _IO_flockfile(stream: *mut c_void) {
        unsafe { flockfile(stream) }
    }

    /// `_IO_funlockfile` — glibc internal funlockfile.
    #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
    pub unsafe extern "C" fn _IO_funlockfile(stream: *mut c_void) {
        unsafe { funlockfile(stream) }
    }

    /// `_IO_ftrylockfile` — glibc internal ftrylockfile.
    #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
    pub unsafe extern "C" fn _IO_ftrylockfile(stream: *mut c_void) -> c_int {
        unsafe { ftrylockfile(stream) }
    }

    // NOTE: _IO_peekc_locked is defined in io_internal_abi.rs.

    /// `_IO_padn` — write `count` copies of `pad` char to stream. Returns count or EOF.
    #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
    pub unsafe extern "C" fn _IO_padn(stream: *mut c_void, pad: c_int, count: isize) -> isize {
        if count <= 0 {
            return 0;
        }
        for _ in 0..count {
            if unsafe { fputc(pad, stream) } == libc::EOF {
                return libc::EOF as isize;
            }
        }
        count
    }

    /// `_IO_sgetn` — read `n` bytes from stream into buffer. Returns bytes read.
    #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
    pub unsafe extern "C" fn _IO_sgetn(stream: *mut c_void, buf: *mut c_void, n: usize) -> usize {
        unsafe { fread(buf, 1, n, stream) }
    }

    /// `_IO_seekoff` — seek to offset in stream (internal interface).
    #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
    pub unsafe extern "C" fn _IO_seekoff(
        stream: *mut c_void,
        offset: i64,
        dir: c_int,
        _mode: c_int,
    ) -> i64 {
        if unsafe { fseeko(stream, offset, dir) } != 0 {
            return -1;
        }
        unsafe { ftello(stream) }
    }

    /// `_IO_seekpos` — seek to absolute position (internal interface).
    #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
    pub unsafe extern "C" fn _IO_seekpos(stream: *mut c_void, pos: i64, _mode: c_int) -> i64 {
        if unsafe { fseeko(stream, pos, libc::SEEK_SET) } != 0 {
            return -1;
        }
        pos
    }

    // `_IO_2_1_{stdin,stdout,stderr}_` are exported by the outer module as
    // aliases to `stdin/stdout/stderr`, so all six names resolve to the same
    // NativeFile-backed standard stream cells.
} // mod _io_internal
pub use _io_internal::*;
