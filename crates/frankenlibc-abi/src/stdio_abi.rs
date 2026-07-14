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

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use frankenlibc_core::errno;
use frankenlibc_core::stdio::{
    BufMode, OpenFlags, ReadUntil, StdioStream, flags_to_oflags, parse_mode,
};
use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction, RuntimeDecision};

use crate::errno_abi::set_abi_errno;
use crate::io_internal_abi::{self, NativeFileBufMode};
use crate::malloc_abi::{free, known_remaining, malloc};
use crate::runtime_policy;
use crate::unistd_abi::{sys_read_fd, sys_write_fd};
use crate::util::{ArtifactHashMap, artifact_hash_map};

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

const LITERAL_FORMAT_CACHE_SIZE: usize = 64;

struct LiteralFormatCacheEntry {
    key: AtomicUsize,
    len: AtomicUsize,
}

impl LiteralFormatCacheEntry {
    const fn new() -> Self {
        Self {
            key: AtomicUsize::new(0),
            len: AtomicUsize::new(0),
        }
    }
}

static LITERAL_FORMAT_CACHE: [LiteralFormatCacheEntry; LITERAL_FORMAT_CACHE_SIZE] =
    [const { LiteralFormatCacheEntry::new() }; LITERAL_FORMAT_CACHE_SIZE];
static READ_ONLY_MAPPINGS: OnceLock<Vec<(usize, usize)>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn repair_enabled(heals_enabled: bool, action: MembraneAction) -> bool {
    heals_enabled || matches!(action, MembraneAction::Repair(_))
}

#[inline]
#[cfg_attr(feature = "standalone", allow(dead_code))]
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
unsafe fn strict_c_str_len(ptr: *const c_char) -> (usize, bool) {
    if runtime_policy::strict_passthrough_active() {
        unsafe { crate::string_abi::scan_c_string(ptr, None) }
    } else {
        unsafe { scan_c_str_len(ptr, None) }
    }
}

// PERF CHOKEPOINT (bd-2g7oyh):
// This helper is the shared format-string length scan for the ENTIRE printf family
// (printf/fprintf/sprintf/snprintf/vprintf/vsnprintf/dprintf/asprintf — ~12 entry
// points each call `c_str_bytes(format)`) and other caller-string sites. Strict mode
// uses `string_abi::scan_c_string(ptr, None)` (page-safe SWAR, no allocation-table
// lock); hardened mode keeps `scan_c_str_len` and its known_remaining bound. NOT
// byte-identical for the UB case (a tracked-but-unterminated buffer: the bound stops
// at the alloc end, scan_c_string scans to NUL = glibc-compatible) — same caveat as
// the sscanf/scanf_core levers, so gate on strict + verify with printf/scanf
// conformance.
#[inline]
pub(crate) unsafe fn c_str_bytes<'a>(ptr: *const c_char) -> &'a [u8] {
    let (len, _) = unsafe { strict_c_str_len(ptr) };
    // SAFETY: the selected C-string scan reached the first NUL byte, so this range is readable.
    unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) }
}

#[derive(Clone, Copy)]
struct StrictDecimalIntsScan {
    count: c_int,
    input_failure: bool,
    values: [c_int; 3],
}

enum StrictIntScan {
    Value(c_int, *const u8),
    InputEnd,
    MatchFail,
}

#[inline]
fn scanf_ascii_space(b: u8) -> bool {
    b == b' ' || (b >= b'\t' && b <= b'\r')
}

#[inline]
unsafe fn strict_decimal_int_format_count(format: *const c_char) -> Option<usize> {
    let f = format.cast::<u8>();
    if unsafe { *f } != b'%' || unsafe { *f.add(1) } != b'd' {
        return None;
    }
    match unsafe { *f.add(2) } {
        0 => Some(1),
        b' ' => {
            if unsafe { *f.add(3) } != b'%' || unsafe { *f.add(4) } != b'd' {
                return None;
            }
            match unsafe { *f.add(5) } {
                0 => Some(2),
                b' ' => {
                    if unsafe { *f.add(6) } == b'%'
                        && unsafe { *f.add(7) } == b'd'
                        && unsafe { *f.add(8) } == 0
                    {
                        Some(3)
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

#[inline]
fn clamp_scanf_i64_magnitude(val: u64, negative: bool, overflowed: bool) -> i64 {
    if negative {
        const MIN_MAGNITUDE: u64 = 1u64 << 63;
        if overflowed || val > MIN_MAGNITUDE {
            i64::MIN
        } else if val == MIN_MAGNITUDE {
            i64::MIN
        } else {
            -(val as i64)
        }
    } else if overflowed || val > i64::MAX as u64 {
        i64::MAX
    } else {
        val as i64
    }
}

#[inline]
unsafe fn strict_scan_decimal_int(mut p: *const u8) -> StrictIntScan {
    loop {
        let b = unsafe { *p };
        if !scanf_ascii_space(b) {
            break;
        }
        p = unsafe { p.add(1) };
    }

    let mut b = unsafe { *p };
    if b == 0 {
        return StrictIntScan::InputEnd;
    }

    let negative = match b {
        b'-' => {
            p = unsafe { p.add(1) };
            true
        }
        b'+' => {
            p = unsafe { p.add(1) };
            false
        }
        _ => false,
    };

    let mut val = 0u64;
    let mut overflowed = false;
    let mut any_digit = false;
    loop {
        b = unsafe { *p };
        if !b.is_ascii_digit() {
            break;
        }
        any_digit = true;
        let d = (b - b'0') as u64;
        match val.checked_mul(10).and_then(|v| v.checked_add(d)) {
            Some(next) => val = next,
            None => {
                val = u64::MAX;
                overflowed = true;
            }
        }
        p = unsafe { p.add(1) };
    }

    if !any_digit {
        return StrictIntScan::MatchFail;
    }

    let wide = clamp_scanf_i64_magnitude(val, negative, overflowed);
    StrictIntScan::Value(wide as c_int, p)
}

#[inline]
unsafe fn strict_scan_decimal_ints(s: *const c_char, fields: usize) -> StrictDecimalIntsScan {
    let mut p = s.cast::<u8>();
    let mut values = [0; 3];
    let mut count = 0usize;
    for slot in values.iter_mut().take(fields) {
        match unsafe { strict_scan_decimal_int(p) } {
            StrictIntScan::Value(value, next) => {
                *slot = value;
                p = next;
                count += 1;
            }
            StrictIntScan::InputEnd => {
                return StrictDecimalIntsScan {
                    count: if count == 0 {
                        libc::EOF
                    } else {
                        count as c_int
                    },
                    input_failure: count == 0,
                    values,
                };
            }
            StrictIntScan::MatchFail => {
                return StrictDecimalIntsScan {
                    count: count as c_int,
                    input_failure: false,
                    values,
                };
            }
        }
    }
    StrictDecimalIntsScan {
        count: fields as c_int,
        input_failure: false,
        values,
    }
}

/// Take at most `limit` WIDE CHARACTERS (Unicode scalar values) from the leading
/// VALID-UTF-8 prefix of `bytes`, returning `(utf8_of_those_chars, char_count)`.
/// Used by WIDE printf `%s`, where the `char*` multibyte content converts to wide
/// characters and precision/width count wide characters, not bytes (C99). Decoding
/// stops at the first invalid byte (glibc would error the conversion there).
fn utf8_take_chars(bytes: &[u8], limit: Option<usize>) -> (Vec<u8>, usize) {
    let valid = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        // The prefix up to `valid_up_to()` is guaranteed valid UTF-8.
        Err(e) => core::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or(""),
    };
    match limit {
        None => (valid.as_bytes().to_vec(), valid.chars().count()),
        Some(p) => {
            let cut = valid
                .char_indices()
                .nth(p)
                .map(|(i, _)| i)
                .unwrap_or(valid.len());
            let taken = &valid.as_bytes()[..cut];
            (taken.to_vec(), valid[..cut].chars().count())
        }
    }
}

/// Largest length `<= limit` that lands on a UTF-8 character boundary. Used to
/// apply `%ls` precision as a BYTE cap on the multibyte output without ever
/// splitting (writing a partial) multibyte character, per C99 §7.19.6.1.
fn utf8_byte_limit(bytes: &[u8], limit: usize) -> usize {
    if limit >= bytes.len() {
        return bytes.len();
    }
    let mut cut = limit;
    // A UTF-8 continuation byte is `0b10xxxxxx`; back up off any partial char.
    while cut > 0 && (bytes[cut] & 0b1100_0000) == 0b1000_0000 {
        cut -= 1;
    }
    cut
}

/// Read a NUL-terminated wide string (`wchar_t*`, `u32` on Linux x86_64) and
/// encode it as UTF-8 (the C.UTF-8 multibyte form), taking at most `limit` WIDE
/// characters when provided (callers that need byte-precision pass `None` and
/// truncate the result with [`utf8_byte_limit`]).
/// Returns `(utf8_bytes, wide_char_count)`.
unsafe fn wide_cstr_to_utf8(ptr: *const u32, limit: Option<usize>) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        if let Some(n) = limit
            && i >= n
        {
            break;
        }
        // SAFETY: caller guarantees a NUL-terminated wide string; we stop at the
        // terminator (and at `limit` wide chars when set).
        let wc = unsafe { *ptr.add(i) };
        if wc == 0 {
            break;
        }
        match char::from_u32(wc) {
            Some(c) => {
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
            // Invalid wide char (surrogate / > U+10FFFF): glibc would error the
            // whole call; we stop the conversion here (rare in practice).
            None => break,
        }
        i += 1;
    }
    (out, i)
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

#[derive(Clone)]
struct StreamIdHasher {
    state: u64,
}

impl Default for StreamIdHasher {
    fn default() -> Self {
        Self {
            state: 0xcbf2_9ce4_8422_2325,
        }
    }
}

impl Hasher for StreamIdHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        for byte in bytes {
            self.state ^= u64::from(*byte);
            self.state = self.state.wrapping_mul(PRIME);
        }
    }

    #[inline]
    fn write_u64(&mut self, value: u64) {
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        self.state ^= value;
        self.state = self.state.wrapping_mul(PRIME);
    }

    #[inline]
    fn write_usize(&mut self, value: usize) {
        self.write_u64(value as u64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.state
    }
}

type StreamIdBuildHasher = BuildHasherDefault<StreamIdHasher>;
type StreamMap<V> = HashMap<usize, V, StreamIdBuildHasher>;

#[inline]
fn stream_map<V>() -> StreamMap<V> {
    StreamMap::default()
}

struct FastRegistryMutex<T> {
    inner: parking_lot::Mutex<T>,
}

struct FastRegistryPoisonError<G> {
    _marker: std::marker::PhantomData<G>,
}

struct FastRegistryLockResult<G> {
    guard: G,
}

impl<T> FastRegistryMutex<T> {
    fn new(value: T) -> Self {
        Self {
            inner: parking_lot::Mutex::new(value),
        }
    }

    fn lock(&self) -> FastRegistryLockResult<parking_lot::MutexGuard<'_, T>> {
        FastRegistryLockResult {
            guard: self.inner.lock(),
        }
    }

    fn try_lock(&self) -> Result<parking_lot::MutexGuard<'_, T>, ()> {
        self.inner.try_lock().ok_or(())
    }
}

impl<G> FastRegistryPoisonError<G> {
    fn into_inner(self) -> G {
        unreachable!("parking_lot mutexes do not poison")
    }
}

impl<G> FastRegistryLockResult<G> {
    fn unwrap_or_else<F>(self, _f: F) -> G
    where
        F: FnOnce(FastRegistryPoisonError<G>) -> G,
    {
        self.guard
    }
}

struct FastFixedMemRead {
    data: Vec<u8>,
    pos: AtomicUsize,
    eof: AtomicBool,
    closed: AtomicBool,
}

impl FastFixedMemRead {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            pos: AtomicUsize::new(0),
            eof: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    #[inline]
    fn read_byte(&self) -> Option<u8> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        loop {
            let pos = self.pos.load(Ordering::Acquire);
            if pos >= self.data.len() {
                self.eof.store(true, Ordering::Release);
                return None;
            }
            if self
                .pos
                .compare_exchange_weak(pos, pos + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.eof.store(false, Ordering::Release);
                return Some(self.data[pos]);
            }
        }
    }

    #[inline]
    fn seek(&self, offset: i64, whence: c_int) -> Option<usize> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let len = self.data.len();
        let current = self.pos.load(Ordering::Acquire).min(len);
        let base = match whence {
            libc::SEEK_SET => 0i64,
            libc::SEEK_CUR => current as i64,
            libc::SEEK_END => len as i64,
            _ => return None,
        };
        let next = base.checked_add(offset)?;
        if next < 0 || next as usize > len {
            return None;
        }
        let next = next as usize;
        self.pos.store(next, Ordering::Release);
        self.eof.store(false, Ordering::Release);
        Some(next)
    }

    #[inline]
    fn sync_to_stream(&self, stream: &mut StdioStream) {
        let pos = self.pos.load(Ordering::Acquire).min(self.data.len());
        let _ = stream.mem_seek(pos as i64, libc::SEEK_SET);
        if self.eof.load(Ordering::Acquire) {
            stream.set_eof();
        }
    }
}

type FastFixedMemReadMap = StreamMap<Arc<FastFixedMemRead>>;

thread_local! {
    static FAST_FIXED_MEM_READ_CACHE: RefCell<Option<(usize, Arc<FastFixedMemRead>)>> =
        const { RefCell::new(None) };
}

fn fast_fixed_mem_reads() -> &'static FastRegistryMutex<FastFixedMemReadMap> {
    static MAP: OnceLock<FastRegistryMutex<FastFixedMemReadMap>> = OnceLock::new();
    MAP.get_or_init(|| FastRegistryMutex::new(stream_map()))
}

fn register_fast_fixed_mem_read(id: usize, data: Vec<u8>) {
    let cursor = Arc::new(FastFixedMemRead::new(data));
    let mut map = fast_fixed_mem_reads()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    map.insert(id, cursor);
}

fn fast_fixed_mem_read(id: usize) -> Option<Arc<FastFixedMemRead>> {
    FAST_FIXED_MEM_READ_CACHE.with(|cache| {
        if let Some((cached_id, cursor)) = cache.borrow().as_ref()
            && *cached_id == id
            && !cursor.closed.load(Ordering::Acquire)
        {
            return Some(Arc::clone(cursor));
        }

        let cursor = {
            let map = fast_fixed_mem_reads()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            map.get(&id).cloned()
        }?;
        if cursor.closed.load(Ordering::Acquire) {
            return None;
        }
        *cache.borrow_mut() = Some((id, Arc::clone(&cursor)));
        Some(cursor)
    })
}

thread_local! {
    /// Pointer-keyed fmemopen `fgetc` fast path: caches the `Arc<FastFixedMemRead>` for a stream
    /// `FILE*` so repeated reads skip `canonical_stream_id` (native lock — the dominant per-byte
    /// cost for mem streams, which the write-cache fast path EXCLUDES) + `decide` + the
    /// `fast_fixed_mem_reads` map lock. MT-SAFE (unlike the ST-gated write cache): the cursor is
    /// `Arc` (held here ⇒ stays alive) + atomic `pos`; thread-local ⇒ no cross-thread race. `gen`
    /// (`REGISTRY_GEN`, bumped by every fmemopen/fclose) invalidates on register/unregister and
    /// on pointer reuse; `read_byte`'s `closed` check invalidates on ungetc/fseek (which
    /// `sync_and_unregister_fast_fixed_mem_read` the cursor) ⇒ falls through to the pushback-aware
    /// slow path. Inherits the exact read semantics of the existing `fast_fixed_mem_read` path.
    static FGETC_MEM_PTR_CACHE: RefCell<Option<(usize, u64, Arc<FastFixedMemRead>)>> =
        const { RefCell::new(None) };
}

/// Pointer-keyed fmemopen read fast path. `Some(byte)` on a gen-valid, open, non-empty cached
/// cursor; `None` on any miss (uncached / gen-stale / closed / EOF) ⇒ caller falls through.
fn try_fgetc_fast_fixed_mem_by_stream(stream: *mut c_void) -> Option<c_int> {
    let key = stream as usize;
    let cur_gen = REGISTRY_GEN.load(Ordering::Acquire);
    FGETC_MEM_PTR_CACHE.with(|c| {
        let cache = c.borrow();
        let (cp, cg, cursor) = cache.as_ref()?;
        if *cp != key || *cg != cur_gen {
            return None;
        }
        cursor.read_byte().map(|b| b as c_int)
    })
}

/// Populate the pointer cache after a slow-path resolve confirms `stream` is a fixed-mem reader.
fn store_fgetc_mem_ptr_cache(stream: *mut c_void, cursor: &Arc<FastFixedMemRead>) {
    let cur_gen = REGISTRY_GEN.load(Ordering::Acquire);
    FGETC_MEM_PTR_CACHE.with(|c| {
        *c.borrow_mut() = Some((stream as usize, cur_gen, Arc::clone(cursor)));
    });
}

fn sync_fast_fixed_mem_read_to_stream(id: usize, stream: &mut StdioStream) -> bool {
    let Some(cursor) = fast_fixed_mem_read(id) else {
        return false;
    };
    cursor.sync_to_stream(stream);
    true
}

fn unregister_fast_fixed_mem_read(id: usize) {
    let cursor = {
        let mut map = fast_fixed_mem_reads()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.remove(&id)
    };
    if let Some(cursor) = cursor {
        cursor.closed.store(true, Ordering::Release);
    }
    FAST_FIXED_MEM_READ_CACHE.with(|cache| {
        let clear = cache
            .borrow()
            .as_ref()
            .is_some_and(|(cached_id, _)| *cached_id == id);
        if clear {
            *cache.borrow_mut() = None;
        }
    });
}

fn sync_and_unregister_fast_fixed_mem_read(id: usize, stream: &mut StdioStream) {
    let _ = sync_fast_fixed_mem_read_to_stream(id, stream);
    unregister_fast_fixed_mem_read(id);
}

struct StreamRegistry {
    streams: StreamMap<StdioStream>,
}

impl StreamRegistry {
    fn new() -> Self {
        let mut streams = stream_map();

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

    /// Insert a runtime stream, bumping the registry generation. ALL runtime
    /// `streams.insert` MUST route through here so the write cache's stored
    /// `*mut StdioStream` is invalidated whenever a HashMap insert may rehash/move
    /// values. (The 3 std streams in `new()` are pre-registration and never cached
    /// before init completes, so they bypass the counter.)
    #[inline]
    fn insert_stream(&mut self, id: usize, stream: StdioStream) {
        REGISTRY_GEN.fetch_add(1, Ordering::Release);
        self.streams.insert(id, stream);
    }

    /// Remove a stream, bumping the registry generation (a remove backshifts other
    /// entries, moving values — must invalidate the write cache).
    #[inline]
    fn remove_stream(&mut self, id: usize) -> Option<StdioStream> {
        REGISTRY_GEN.fetch_add(1, Ordering::Release);
        self.streams.remove(&id)
    }
}

/// Monotonic generation bumped on every runtime registry insert/remove (via
/// `insert_stream`/`remove_stream`). The single-threaded write fast-path caches a
/// `*mut StdioStream` together with the gen at which it was resolved; a mismatch on a
/// later call means the HashMap may have moved that value, so the cache is dropped and
/// the slow (locked) path re-resolves. Lock-free read for the hot path.
static REGISTRY_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

thread_local! {
    /// Per-thread last-written stream cache: (canonical id, registry gen, raw stream).
    /// Lets repeated single-char writes to the same stream skip the membrane + registry
    /// lock + HashMap lookup. Only consulted while `__libc_single_threaded` (so the
    /// `&mut` reborrow of `ptr` is the unique reference — no other thread exists), and
    /// only used when `gen == REGISTRY_GEN` (value not moved since it was cached).
    /// 2-way (most-recent-first) so a loop interleaving writes to TWO streams (stdout +
    /// a log file, app + access log — measured 1.58x thrash on the old single entry) keeps
    /// BOTH resolved lock-free instead of missing every alternating call.
    static WRITE_CACHE: std::cell::Cell<[(usize, u64, *mut StdioStream); 2]> =
        const { std::cell::Cell::new([(usize::MAX, 0, std::ptr::null_mut()); 2]) };
}

/// Returns the cached `*mut StdioStream` for `id` iff single-threaded and the cache is
/// gen-valid (value not moved since caching). The caller dereferences it without the
/// registry lock — sound only because single-threaded ⇒ no concurrent access.
#[inline]
fn write_cache_lookup(id: usize) -> Option<*mut StdioStream> {
    if crate::glibc_internal_abi::__libc_single_threaded.load(Ordering::Acquire) == 0 {
        return None;
    }
    let cur_gen = REGISTRY_GEN.load(Ordering::Acquire);
    WRITE_CACHE.with(|c| {
        for (cid, cgen, p) in c.get() {
            if cid == id && !p.is_null() && cgen == cur_gen {
                return Some(p);
            }
        }
        None
    })
}

/// Pointer-keyed sibling of `write_cache_lookup`: resolve a raw `FILE*` to its cached
/// `StdioStream*` WITHOUT calling `canonical_stream_id`. The cached id is exactly
/// `canonical_stream_id(stream)`, which for both fl's own std streams (sentinel address)
/// and fl-owned non-std streams equals `stream as usize` (a non-std id IS the pointer).
/// So `cid == stream as usize` is a valid hit — and it skips `standard_stream_id`'s
/// `native_stdio_fd_for_ptr` lock, which otherwise fires on EVERY fputs/fputc/fwrite to a
/// non-std stream (fopen'd files/pipes) purely to rule out the 3 native glibc std FILE*s
/// (~20ns uncontended lock, the dominant cost of the single-threaded write fast path vs
/// glibc's lock-free append). A miss (rare: a genuine host-glibc std FILE* passed in, or
/// first write) falls through to the `canonical_stream_id` path unchanged. Same ST +
/// gen-validity soundness gates as `write_cache_lookup`.
#[inline]
fn write_cache_lookup_by_stream(stream: *mut c_void) -> Option<*mut StdioStream> {
    if crate::glibc_internal_abi::__libc_single_threaded.load(Ordering::Acquire) == 0 {
        return None;
    }
    let key = stream as usize;
    let cur_gen = REGISTRY_GEN.load(Ordering::Acquire);
    WRITE_CACHE.with(|c| {
        for (cid, cgen, p) in c.get() {
            if cid == key && !p.is_null() && cgen == cur_gen {
                return Some(p);
            }
        }
        None
    })
}

/// Records the resolved `*mut StdioStream` for `id` (called on the slow path under the
/// registry lock, capturing the gen so a later insert/remove invalidates it).
#[inline]
fn write_cache_store(id: usize, ptr: *mut StdioStream) {
    let generation = REGISTRY_GEN.load(Ordering::Acquire);
    // Insert-at-front (most-recent-first), shifting the previous head to slot 1. `store`
    // only runs on a full cache miss (a lookup hit returns before storing), so `id` is not
    // already resident — no duplicate slot. 2-way holds two hot streams (interleave-safe).
    WRITE_CACHE.with(|c| {
        let old = c.get();
        c.set([(id, generation, ptr), old[0]]);
    });
}

/// Single-threaded fast path for single-byte writes: if `id` resolves through the
/// gen-valid thread-local cache to a Full-buffered fd stream with room, append the byte
/// inline — skipping the membrane (`decide`/`observe`/`entrypoint_scope`), the registry
/// lock, and the HashMap lookup. Returns `Some(byte)` on success, `None` to fall back to
/// the full path. The cache only ever holds non-cookie, non-mem fd streams (stored solely
/// on the regular slow path), so `fast_putc`'s semantics are exactly `buffer_write`'s
/// no-flush branch. SOUND: `write_cache_lookup` already gated on `__libc_single_threaded`
/// (unique `&mut`) and gen-validity (value not moved).
#[inline]
fn try_fputc_fast(id: usize, byte: u8) -> Option<c_int> {
    let p = write_cache_lookup(id)?;
    // SAFETY: single-threaded ⇒ no other thread; gen-valid ⇒ the value has not moved
    // since it was cached; the reborrow is the unique reference for this call only.
    if unsafe { (*p).fast_putc(byte) } {
        Some(byte as c_int)
    } else {
        None
    }
}

/// Pointer-keyed sibling of `try_fputc_fast`: resolves via `write_cache_lookup_by_stream`
/// so the fast path skips `canonical_stream_id`'s `native_stdio_fd_for_ptr` lock (measured
/// ~6ns/call saved, ~21% of fd fputc). Same soundness gates.
#[inline]
fn try_fputc_fast_by_stream(stream: *mut c_void, byte: u8) -> Option<c_int> {
    let p = write_cache_lookup_by_stream(stream)?;
    // SAFETY: as `try_fputc_fast`.
    if unsafe { (*p).fast_putc(byte) } {
        Some(byte as c_int)
    } else {
        None
    }
}

/// Bulk sibling of `try_fputc_fast` for `fputs`/`fwrite`: if `id` resolves through the
/// gen-valid single-threaded cache to a Full-buffered fd stream with room for all of
/// `bytes`, append them inline (skipping membrane + lock + lookup) and return `true`.
#[inline]
fn try_fwrite_fast(id: usize, bytes: &[u8]) -> bool {
    match write_cache_lookup(id) {
        // SAFETY: single-threaded (lookup-gated) ⇒ unique &mut; gen-valid ⇒ not moved.
        Some(p) => unsafe { (*p).fast_write(bytes) },
        None => false,
    }
}

/// Pointer-keyed sibling of `try_fwrite_fast`: resolves via `write_cache_lookup_by_stream`
/// so the fast path skips `canonical_stream_id`'s `native_stdio_fd_for_ptr` lock. Same gates.
#[inline]
fn try_fwrite_fast_by_stream(stream: *mut c_void, bytes: &[u8]) -> bool {
    match write_cache_lookup_by_stream(stream) {
        // SAFETY: as `try_fwrite_fast`.
        Some(p) => unsafe { (*p).fast_write(bytes) },
        None => false,
    }
}

/// Read sibling of `try_fputc_fast` for `fgetc`/`getc`: if `id` resolves through the
/// gen-valid single-threaded cache to a clean readable fd stream with a byte already
/// buffered, return it inline (skipping membrane + lock + lookup). `None` ⇒ full path
/// (refill / ungetc / mem / transition). The cache is populated for read streams on the
/// fgetc slow path below, mirroring the write side.
#[inline]
fn try_fgetc_fast(id: usize) -> Option<c_int> {
    let p = write_cache_lookup(id)?;
    // SAFETY: single-threaded (lookup-gated) ⇒ unique &mut; gen-valid ⇒ not moved.
    unsafe { (*p).fast_getc() }.map(|b| b as c_int)
}

/// Pointer-keyed sibling of `try_fgetc_fast`: skips `canonical_stream_id`'s native lock on a
/// hit (the read analog of the write fast-path win). Same soundness gates.
#[inline]
fn try_fgetc_fast_by_stream(stream: *mut c_void) -> Option<c_int> {
    let p = write_cache_lookup_by_stream(stream)?;
    // SAFETY: as `try_fgetc_fast`.
    unsafe { (*p).fast_getc() }.map(|b| b as c_int)
}

/// Bulk read sibling of `try_fgetc_fast` for `fread`: fills `dst` inline iff all of it is
/// already buffered for the cached single-threaded fd stream (skip membrane + lock +
/// lookup). `false` ⇒ full path (refill / partial / mem).
#[inline]
fn try_fread_fast(id: usize, dst: &mut [u8]) -> bool {
    match write_cache_lookup(id) {
        // SAFETY: single-threaded (lookup-gated) ⇒ unique &mut; gen-valid ⇒ not moved.
        Some(p) => unsafe { (*p).fast_read(dst) },
        None => false,
    }
}

/// Pointer-keyed sibling of `try_fread_fast`: skips `canonical_stream_id`'s native lock on a hit.
#[inline]
fn try_fread_fast_by_stream(stream: *mut c_void, dst: &mut [u8]) -> bool {
    match write_cache_lookup_by_stream(stream) {
        // SAFETY: as `try_fread_fast`.
        Some(p) => unsafe { (*p).fast_read(dst) },
        None => false,
    }
}

fn sorted_stream_ids(reg: &StreamRegistry) -> Vec<usize> {
    let mut ids: Vec<usize> = reg.streams.keys().copied().collect();
    ids.sort_unstable();
    ids
}

fn registry() -> &'static FastRegistryMutex<StreamRegistry> {
    ensure_host_libio_exit_safe();

    use std::sync::atomic::{AtomicPtr, Ordering};
    static PTR: AtomicPtr<FastRegistryMutex<StreamRegistry>> = AtomicPtr::new(std::ptr::null_mut());
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
        let reg = Box::new(FastRegistryMutex::new(StreamRegistry::new()));
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
#[allow(dead_code)]
struct HostStreamState {
    io_started: bool,
}

#[allow(dead_code)]
fn host_stream_registry() -> &'static Mutex<ArtifactHashMap<usize, HostStreamState>> {
    static HOST_STREAMS: OnceLock<Mutex<ArtifactHashMap<usize, HostStreamState>>> = OnceLock::new();
    HOST_STREAMS.get_or_init(|| Mutex::new(artifact_hash_map()))
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
fn host_stream_io_started(id: usize) -> bool {
    let guard = host_stream_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    guard
        .get(&id)
        .map(|state| state.io_started)
        .unwrap_or(false)
}

#[allow(dead_code)]
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
#[allow(clippy::needless_return)]
fn standard_stream_id(stream: *mut c_void) -> Option<usize> {
    if stream.is_null() {
        return None;
    }
    let addr = stream as usize;

    // In standalone mode, only match sentinel addresses (no host glibc FILE* comparison).
    #[cfg(feature = "standalone")]
    {
        return match addr {
            STDIN_SENTINEL => Some(STDIN_SENTINEL),
            STDOUT_SENTINEL => Some(STDOUT_SENTINEL),
            STDERR_SENTINEL => Some(STDERR_SENTINEL),
            _ => None,
        };
    }

    #[cfg(not(feature = "standalone"))]
    {
        // Check the 3 sentinel ADDRESSES first (cheap integer compares): fl's own
        // stdin/stdout/stderr are sentinels, so the hot stdout/stderr write path
        // resolves here with ZERO `native_stream_registry` locks. Previously each
        // branch's `|| stream == native_stdio_stream_ptr(fd)` took that std::sync
        // mutex (a stdout write paid the STDIN-branch lock; a non-std stream paid all
        // 3). Byte-identical ptr->id mapping. (bd-hqo6b6 hot-path; cc/BoldFalcon)
        match addr {
            STDIN_SENTINEL => return Some(STDIN_SENTINEL),
            STDOUT_SENTINEL => return Some(STDOUT_SENTINEL),
            STDERR_SENTINEL => return Some(STDERR_SENTINEL),
            _ => {}
        }
        // Non-sentinel pointer: a single locked check against the 3 native FILE slots
        // (was up to 3 separate locked calls).
        match io_internal_abi::native_stdio_fd_for_ptr(stream) {
            Some(libc::STDIN_FILENO) => Some(STDIN_SENTINEL),
            Some(libc::STDOUT_FILENO) => Some(STDOUT_SENTINEL),
            Some(libc::STDERR_FILENO) => Some(STDERR_SENTINEL),
            _ => None,
        }
    }
}

#[inline]
fn canonical_stream_id(stream: *mut c_void) -> usize {
    standard_stream_id(stream).unwrap_or(stream as usize)
}

/// Bench hook: cost of `canonical_stream_id` (the per-call FILE*->id mapping, which for a
/// non-std stream takes the `native_stdio_fd_for_ptr` lock). Not part of the ABI.
#[doc(hidden)]
pub fn bench_canonical_stream_id_cost(stream: *mut c_void) -> usize {
    canonical_stream_id(stream)
}

/// Bench hook: OLD fputs fast-path lookup (canonical_stream_id + by-id cache) + fast_write.
/// # Safety: `s` NUL-terminated; `stream` a cached writable stream.
#[doc(hidden)]
pub unsafe fn bench_fputs_oldpath(s: *const c_char, stream: *mut c_void) -> bool {
    let id = canonical_stream_id(stream);
    if let Some(p) = write_cache_lookup(id) {
        let (len, _) = unsafe { scan_c_str_len(s, None) };
        let bytes = unsafe { std::slice::from_raw_parts(s as *const u8, len) };
        return unsafe { (*p).fast_write(bytes) };
    }
    false
}

/// Bench hook: NEW fputs fast-path lookup (pointer-keyed, skips canonical_stream_id) + fast_write.
/// # Safety: `s` NUL-terminated; `stream` a cached writable stream.
#[doc(hidden)]
pub unsafe fn bench_fputs_newpath(s: *const c_char, stream: *mut c_void) -> bool {
    if let Some(p) = write_cache_lookup_by_stream(stream) {
        let (len, _) = unsafe { scan_c_str_len(s, None) };
        let bytes = unsafe { std::slice::from_raw_parts(s as *const u8, len) };
        return unsafe { (*p).fast_write(bytes) };
    }
    false
}

/// Bench hook: OLD feof path (canonical_stream_id + registry lock + get + is_eof).
#[doc(hidden)]
pub fn bench_feof_oldpath(stream: *mut c_void) -> c_int {
    let id = canonical_stream_id(stream);
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        let _ = sync_fast_fixed_mem_read_to_stream(id, s);
        if s.is_eof() { 1 } else { 0 }
    } else {
        0
    }
}

/// Bench hook: NEW feof fast path (pointer-keyed, lock-free is_eof).
#[doc(hidden)]
pub fn bench_feof_newpath(stream: *mut c_void) -> c_int {
    if let Some(p) = write_cache_lookup_by_stream(stream) {
        return if unsafe { (*p).is_eof() } { 1 } else { 0 };
    }
    0
}

/// Bench hook: OLD fgets path (canonical_stream_id + registry lock + fill). Not part of the ABI.
#[doc(hidden)]
pub unsafe fn bench_fgets_oldpath(
    buf: *mut c_char,
    size: c_int,
    stream: *mut c_void,
) -> *mut c_char {
    let id = canonical_stream_id(stream);
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        return std::ptr::null_mut();
    };
    let max = (size - 1) as usize;
    if s.is_mem_backed() {
        sync_and_unregister_fast_fixed_mem_read(id, s);
    }
    let dst = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, max) };
    let (written, had_error) = unsafe { fgets_fill_stream(s, dst) };
    if (written == 0 && max > 0) || had_error {
        return std::ptr::null_mut();
    }
    unsafe { *buf.add(written) = 0 };
    buf
}

/// Bench hook: NEW fgets pointer-keyed fast path. Not part of the ABI.
#[doc(hidden)]
pub unsafe fn bench_fgets_newpath(
    buf: *mut c_char,
    size: c_int,
    stream: *mut c_void,
) -> *mut c_char {
    if let Some(p) = write_cache_lookup_by_stream(stream) {
        let max = (size - 1) as usize;
        let dst = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, max) };
        let (written, had_error) = unsafe { fgets_fill_stream(&mut *p, dst) };
        if (written == 0 && max > 0) || had_error {
            return std::ptr::null_mut();
        }
        unsafe { *buf.add(written) = 0 };
        return buf;
    }
    std::ptr::null_mut()
}

/// Snapshot of a stream's state for the `stdio_ext.h` introspection helpers
/// (`__freadable`/`__fwritable`/`__flbf`/`__fbufsize`/`__fpending`).
pub(crate) struct StreamExtInfo {
    pub readable: bool,
    pub writable: bool,
    pub line_buffered: bool,
    pub buf_size: usize,
    pub pending: usize,
    /// glibc `__freading`: read-only OR the last operation was a read.
    pub reading: bool,
    /// glibc `__fwriting`: write-only OR the last operation was a write.
    pub writing: bool,
}

/// Resolve a `FILE*` to its `stdio_ext` introspection state, or `None` if fl
/// does not own the stream (caller falls back to a permissive default).
pub(crate) fn stream_ext_info(stream: *mut c_void) -> Option<StreamExtInfo> {
    let id = canonical_stream_id(stream);
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.get(&id).map(|s| {
        let readable = s.is_readable();
        let writable = s.is_writable();
        StreamExtInfo {
            readable,
            writable,
            line_buffered: matches!(s.buf_mode(), BufMode::Line),
            buf_size: s.buffer_capacity(),
            pending: s.pending_flush().len(),
            // glibc: read-only stream, or last op was a read.
            reading: readable && (!writable || s.last_was_read()),
            // glibc: write-only stream, or last op was a write.
            writing: writable && (!readable || s.last_was_write()),
        }
    })
}

/// `fwide`: apply the orientation `mode` to a stream (sticky once set) and
/// return the resulting orientation (>0 wide, <0 byte, 0 unset). Returns `None`
/// if fl does not own the stream.
pub(crate) fn stream_set_orientation(stream: *mut c_void, mode: c_int) -> Option<c_int> {
    let id = canonical_stream_id(stream);
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.get_mut(&id).map(|s| s.set_orientation(mode))
}

/// `__fsetlocking`: query/set the stream's locking mode, returning the mode in
/// effect before the call (1 = INTERNAL, 2 = BYCALLER). `None` if fl does not
/// own the stream.
pub(crate) fn stream_set_locking(stream: *mut c_void, typ: c_int) -> Option<c_int> {
    let id = canonical_stream_id(stream);
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.streams.get_mut(&id).map(|s| s.set_locking(typ))
}

/// `__fpurge`: discard the stream's buffered (unread/unflushed) data. Returns
/// true if fl owns the stream and purged it.
pub(crate) fn stream_purge(stream: *mut c_void) -> bool {
    let id = canonical_stream_id(stream);
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    match reg.streams.get_mut(&id) {
        Some(s) => {
            sync_and_unregister_fast_fixed_mem_read(id, s);
            s.purge();
            true
        }
        None => false,
    }
}

#[inline]
#[cfg_attr(feature = "standalone", allow(unused_variables))]
fn sync_native_stdio_buffering(stream: *mut c_void, mode: BufMode, buf: *mut c_char, size: usize) {
    // In standalone mode, no host stdio streams to configure.
    #[cfg(not(feature = "standalone"))]
    {
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
}

#[inline]
unsafe fn host_stdio_symbol(slot: &OnceLock<usize>, symbol: &'static str) -> Option<usize> {
    crate::host_resolve::resolve_host_symbol_cached(slot, symbol)
}

#[inline]
#[allow(dead_code)]
unsafe fn sync_host_errno(default_errno: c_int) {
    unsafe { set_abi_errno(crate::host_resolve::host_errno(default_errno)) };
}

#[inline]
#[allow(dead_code)]
unsafe fn host_fwrite_fn() -> Option<HostFwriteFn> {
    unsafe { host_stdio_symbol(&HOST_FWRITE_FN, "fwrite") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_fputs_fn() -> Option<HostFputsFn> {
    unsafe { host_stdio_symbol(&HOST_FPUTS_FN, "fputs") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_fputc_fn() -> Option<HostFputcFn> {
    unsafe { host_stdio_symbol(&HOST_FPUTC_FN, "fputc") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_fclose_fn() -> Option<HostFcloseFn> {
    unsafe { host_stdio_symbol(&HOST_FCLOSE_FN, "fclose") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_fileno_fn() -> Option<HostFilenoFn> {
    unsafe { host_stdio_symbol(&HOST_FILENO_FN, "fileno") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_feof_fn() -> Option<HostFeofFn> {
    unsafe { host_stdio_symbol(&HOST_FEOF_FN, "feof") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_ferror_fn() -> Option<HostFerrorFn> {
    unsafe { host_stdio_symbol(&HOST_FERROR_FN, "ferror") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_clearerr_fn() -> Option<HostClearerrFn> {
    unsafe { host_stdio_symbol(&HOST_CLEARERR_FN, "clearerr") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_fgetc_fn() -> Option<HostFgetcFn> {
    unsafe { host_stdio_symbol(&HOST_FGETC_FN, "fgetc") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_fgets_fn() -> Option<HostFgetsFn> {
    unsafe { host_stdio_symbol(&HOST_FGETS_FN, "fgets") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_fread_fn() -> Option<HostFreadFn> {
    unsafe { host_stdio_symbol(&HOST_FREAD_FN, "fread") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_ungetc_fn() -> Option<HostUngetcFn> {
    unsafe { host_stdio_symbol(&HOST_UNGETC_FN, "ungetc") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_fseek_fn() -> Option<HostFseekFn> {
    unsafe { host_stdio_symbol(&HOST_FSEEK_FN, "fseek") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_ftell_fn() -> Option<HostFtellFn> {
    unsafe { host_stdio_symbol(&HOST_FTELL_FN, "ftell") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_fflush_fn() -> Option<HostFflushFn> {
    unsafe { host_stdio_symbol(&HOST_FFLUSH_FN, "fflush") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_getdelim_fn() -> Option<HostGetdelimFn> {
    unsafe { host_stdio_symbol(&HOST_GETDELIM_FN, "getdelim") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_getline_fn() -> Option<HostGetlineFn> {
    unsafe { host_stdio_symbol(&HOST_GETLINE_FN, "getline") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_setvbuf_fn() -> Option<HostSetvbufFn> {
    unsafe { host_stdio_symbol(&HOST_SETVBUF_FN, "setvbuf") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_vfscanf_fn() -> Option<HostVfscanfFn> {
    unsafe { host_stdio_symbol(&HOST_VFSCANF_FN, "vfscanf") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_fgetpos_fn() -> Option<HostFgetposFn> {
    unsafe { host_stdio_symbol(&HOST_FGETPOS_FN, "fgetpos") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_fsetpos_fn() -> Option<HostFsetposFn> {
    unsafe { host_stdio_symbol(&HOST_FSETPOS_FN, "fsetpos") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_freopen_fn() -> Option<HostFreopenFn> {
    unsafe { host_stdio_symbol(&HOST_FREOPEN_FN, "freopen") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_flockfile_fn() -> Option<HostFlockfileFn> {
    unsafe { host_stdio_symbol(&HOST_FLOCKFILE_FN, "flockfile") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
unsafe fn host_funlockfile_fn() -> Option<HostFunlockfileFn> {
    unsafe { host_stdio_symbol(&HOST_FUNLOCKFILE_FN, "funlockfile") }
        .map(|ptr| unsafe { std::mem::transmute(ptr) })
}

#[inline]
#[allow(dead_code)]
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
    reg.insert_stream(native_ptr as usize, stream);
    native_ptr
}

#[allow(dead_code)]
pub(crate) fn register_stream(stream: StdioStream) -> usize {
    let id = alloc_stream_id();
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.insert_stream(id, stream);
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
    _stream: *mut c_void,
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

    // PERF (bd-hqo6b6): this GLOBAL `registry()` Mutex is the dominant cost of the
    // deployed write path — `fputs`/`fwrite`/`fputc`/`puts` all funnel here and
    // pay one acquisition per call (measured 6-12x slower than glibc end-to-end;
    // see fputs_glibc_bench in NEGATIVE_EVIDENCE.md). glibc does a lock-free inline
    // buffer-pointer bump. The membrane decide/observe and the cookie/memstream
    // registry locks on this path are already eliminated for the common case
    // (this campaign); the main `registry()` lock is what remains. The real fix is
    // architectural: a sharded/per-FILE lock (Arc<Mutex<StdioStream>> resolved via
    // a read-mostly RwLock<HashMap>) so concurrent writes to different streams
    // don't serialize and the single-threaded path can drop to a cheap fast lock.
    // NOT a blind micro-edit — needs a build+test turn with harness conformance.
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream_obj) = reg.streams.get_mut(&id) else {
        drop(reg);
        // Host delegation path - not available in standalone mode
        #[cfg(not(feature = "standalone"))]
        if let Some(host_fwrite) = unsafe { host_fwrite_fn() } {
            let written = unsafe { host_fwrite(bytes.as_ptr().cast(), 1, bytes.len(), _stream) };
            if written == 0 {
                unsafe { sync_host_errno(0) };
            } else {
                mark_host_io_started(_stream);
            }
            return written.min(bytes.len());
        }
        return 0;
    };

    if stream_obj.is_mem_backed() {
        let written = stream_obj.mem_write(bytes);
        if written < bytes.len() {
            stream_obj.set_error();
        }
        return written;
    }

    // Cache this non-cookie, non-mem fd stream so subsequent single-threaded single-byte
    // writes hit the inline fast path (try_fputc_fast). This is the COMMON deployed path
    // (heals disabled), so the cache must be populated here, not only on the membrane path.
    write_cache_store(id, stream_obj as *mut StdioStream);

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
thread_local! {
    /// Reusable refill bounce buffer — refill_stream fires on EVERY buffered read refill
    /// (fgetc/fread/fgets/getline), and a fresh `vec![0u8; <=8192]` per refill is a per-refill
    /// fl-malloc on the read hot path. A thread-local Vec retains capacity across refills;
    /// a drop guard restores it on every return path.
    static REFILL_TMP: std::cell::Cell<Vec<u8>> = const { std::cell::Cell::new(Vec::new()) };
}

struct RefillTmpGuard(Vec<u8>);
impl Drop for RefillTmpGuard {
    fn drop(&mut self) {
        REFILL_TMP.with(|c| c.set(std::mem::take(&mut self.0)));
    }
}

unsafe fn refill_stream(stream: &mut StdioStream) -> isize {
    let capacity = stream.buffer_capacity();
    if capacity == 0 {
        return 0; // Cannot buffer anything.
    }
    let want = capacity.min(8192);
    // Reuse the thread-local bounce buffer (retains capacity) instead of a fresh per-refill
    // Vec. `sys_read_fd` overwrites the first `want` bytes, so no pre-zeroing is required for
    // correctness; `resize(want, 0)` only grows (a no-op once warmed to the common size).
    let mut guard = RefillTmpGuard(REFILL_TMP.with(|c| c.take()));
    let tmp = &mut guard.0;
    if tmp.len() < want {
        tmp.resize(want, 0);
    }
    let fd = stream.fd();
    loop {
        let rc = unsafe { sys_read_fd(fd, tmp.as_mut_ptr().cast(), want) };
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

// glibc internal `_IO_2_1_{stdin,stdout,stderr}_` mirrors.
//
// These names are not pointer cells in glibc; they are the actual `_IO_FILE_plus`
// objects backing the public `stdin/stdout/stderr` pointer variables. Release
// builds therefore must not export them as aliases to the 8-byte pointer cells:
// that creates an ABI lie which makes preloaded processes treat a pointer value
// as a FILE header during dynamic-loader/libc startup.
//
// Debug/test builds do not export the libc symbol surface, so they keep local
// pointer mirrors with the same runtime values for unit-test coverage only.
#[cfg(debug_assertions)]
#[allow(non_upper_case_globals)]
pub static mut IO_2_1_STDIN: *mut c_void = STDIN_SENTINEL as *mut c_void;

#[cfg(debug_assertions)]
#[allow(non_upper_case_globals)]
pub static mut IO_2_1_STDOUT: *mut c_void = STDOUT_SENTINEL as *mut c_void;

#[cfg(debug_assertions)]
#[allow(non_upper_case_globals)]
pub static mut IO_2_1_STDERR: *mut c_void = STDERR_SENTINEL as *mut c_void;

static HOST_STDIO_BOOTSTRAPPED: AtomicBool = AtomicBool::new(false);
#[cfg_attr(feature = "standalone", allow(dead_code))]
static HOST_LIBIO_EXIT_PATCHED: AtomicBool = AtomicBool::new(false);
#[cfg(not(debug_assertions))]
#[cfg_attr(feature = "standalone", allow(dead_code))]
static HOST_STDIO_COPY_RELOCATIONS_SYNCED: AtomicBool = AtomicBool::new(false);

fn ensure_host_libio_exit_safe() {
    // In standalone mode, no host libio to patch.
    #[cfg(not(feature = "standalone"))]
    {
        if HOST_LIBIO_EXIT_PATCHED.load(Ordering::Acquire) {
            return;
        }
        if !runtime_policy::is_runtime_ready() {
            return;
        }
        if HOST_LIBIO_EXIT_PATCHED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            unsafe { io_internal_abi::bootstrap_host_libio_exports() };
        }
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
#[cfg_attr(feature = "standalone", allow(dead_code))]
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
///
/// In standalone mode, stdio globals are already set to sentinel values that map
/// directly to the stream registry entries, so no host delegation is needed.
#[allow(clippy::needless_return)]
pub(crate) fn init_host_stdio_streams() {
    if HOST_STDIO_BOOTSTRAPPED.load(Ordering::Acquire) {
        return;
    }

    // In standalone mode, globals are pre-set to sentinels - just mark as ready.
    #[cfg(feature = "standalone")]
    {
        HOST_STDIO_BOOTSTRAPPED.store(true, Ordering::Release);
    }

    #[cfg(not(feature = "standalone"))]
    {
        ensure_host_libio_exit_safe();

        #[cfg(not(debug_assertions))]
        let can_sync_copy_relocations = runtime_policy::is_runtime_ready()
            && !HOST_STDIO_COPY_RELOCATIONS_SYNCED.load(Ordering::Acquire);
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
                    if can_sync_copy_relocations {
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
                        HOST_STDIO_COPY_RELOCATIONS_SYNCED.store(true, Ordering::Release);
                    }
                }
            }
        }
        HOST_STDIO_BOOTSTRAPPED.store(true, Ordering::Release);
    }
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
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    let mode_bytes = unsafe { std::slice::from_raw_parts(mode as *const u8, mode_len) };
    let Some(open_flags) = parse_mode(mode_bytes) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        unsafe { set_abi_errno(errno::EINVAL) };
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
    reg.insert_stream(id, stream);
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
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
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
    let Some(mut s) = reg.remove_stream(id) else {
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
        sync_and_unregister_fast_fixed_mem_read(id, &mut s);
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

#[doc(hidden)]
pub unsafe fn fflush_managed_only_for_abort() -> c_int {
    let Ok(mut reg) = registry().try_lock() else {
        return libc::EOF;
    };
    let ids = sorted_stream_ids(&reg);
    let mut overall_rc = 0;
    for id in ids {
        if let Some(s) = reg.streams.get_mut(&id) {
            let success = unsafe { flush_stream(s) };
            if !success {
                overall_rc = libc::EOF;
            }
        }
    }
    overall_rc
}

/// POSIX `fflush`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fflush(stream: *mut c_void) -> c_int {
    if !stream.is_null() {
        let _id = canonical_stream_id(stream);
        // Host delegation path - not available in standalone mode
        #[cfg(not(feature = "standalone"))]
        if !registry_contains_stream(_id)
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
        #[allow(unused_mut)]
        let mut host_fail = false;
        // Host delegation path - not available in standalone mode
        #[cfg(not(feature = "standalone"))]
        if let Some(host_fflush) = unsafe { host_fflush_fn() } {
            let rc = unsafe { host_fflush(std::ptr::null_mut()) };
            if rc != 0 {
                host_fail = true;
                unsafe { sync_host_errno(errno::EBADF) };
            }
        }
        let Ok(mut reg) = registry().try_lock() else {
            // Lock held by dead thread (fork) or reentrant. Fail safe.
            return libc::EOF;
        };
        let mut any_fail = false;
        let ids = sorted_stream_ids(&reg);
        for id in ids {
            if let Some(s) = reg.streams.get_mut(&id) {
                let ok = if is_cookie_stream(id) {
                    true
                } else if s.is_mem_backed() {
                    let _ = sync_fast_fixed_mem_read_to_stream(id, s);
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
            let _ = sync_fast_fixed_mem_read_to_stream(id, s);
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
    // Single-threaded inline read fast path: a byte already buffered for a cached, clean
    // readable fd stream — skips membrane + registry lock + HashMap lookup. Pointer-keyed
    // so a hit also skips `canonical_stream_id`'s native lock; `id` computed lazily on miss.
    // Any miss (empty buffer / ungetc / write-pending / mem / not cached) falls through.
    if let Some(rc) = try_fgetc_fast_by_stream(stream) {
        return rc;
    }
    // Pointer-keyed fmemopen read fast path (the write cache above EXCLUDES mem streams, so
    // fmemopen `fgetc` otherwise pays `canonical_stream_id`'s native lock per byte — the 1.4x
    // per-op floor, ST and MT). MT-safe (atomic cursor). Miss ⇒ falls through and re-caches.
    if let Some(rc) = try_fgetc_fast_fixed_mem_by_stream(stream) {
        return rc;
    }

    let id = canonical_stream_id(stream);
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 1, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    }

    if let Some(cursor) = fast_fixed_mem_read(id) {
        // Cache by FILE* so subsequent reads skip `canonical_stream_id` + `decide` (above).
        store_fgetc_mem_ptr_cache(stream, &cursor);
        if let Some(byte) = cursor.read_byte() {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
            return byte as c_int;
        }
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
        drop(reg);
        #[cfg(not(feature = "standalone"))]
        if let Some(host_fgetc) = unsafe { host_fgetc_fn() } {
            let rc = unsafe { host_fgetc(stream) };
            mark_host_io_started(stream);
            if rc == libc::EOF {
                unsafe { sync_host_errno(0) };
            }
            return rc;
        }

        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return libc::EOF;
    };

    // Memory-backed streams: read directly from backing (no per-getc Vec).
    if s.is_mem_backed() {
        let mut b = [0u8; 1];
        if s.mem_read_into(&mut b) == 0 {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
            return libc::EOF;
        }
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
        return b[0] as c_int;
    }

    // Cache this non-cookie, non-mem fd stream so subsequent single-threaded fgetc calls
    // hit the inline read fast path (try_fgetc_fast) — mirrors the write side.
    write_cache_store(id, s as *mut StdioStream);

    // Try buffered read first (into a stack byte, no per-getc Vec).
    let mut b = [0u8; 1];
    if s.buffered_read_into(&mut b) > 0 {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
        return b[0] as c_int;
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
    let byte = c as u8;

    // Single-threaded inline fast path (skips membrane + registry lock + HashMap lookup
    // for repeated writes to the same Full-buffered fd stream). Pointer-keyed so a hit
    // also skips `canonical_stream_id`'s native lock; `id` is computed lazily on miss.
    // It only fires for a stream already resolved+cached by a prior slow write, so
    // bootstrap (empty cache) falls through safely.
    if let Some(rc) = try_fputc_fast_by_stream(stream, byte) {
        return rc;
    }

    let id = canonical_stream_id(stream);

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
        // Host delegation path - not available in standalone mode
        #[cfg(not(feature = "standalone"))]
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
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
        return c;
    }

    // Cache this resolved non-cookie, non-mem fd stream so subsequent single-threaded
    // single-byte writes to it skip the membrane + lock + lookup (see try_fputc_fast).
    write_cache_store(id, s as *mut StdioStream);

    let single_byte = [byte];
    let write_result = match s.buffer_write(&single_byte) {
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
/// Shared fgets fill loop: read from `s` into `dst` until '\n' (inclusive), `dst` full, EOF,
/// or error. Returns `(bytes_written, had_error)`. Scans the stream buffer for '\n' via
/// `read_into_slice` (bulk, no per-char Vec) and refills the fd as needed. Sound whether the
/// caller holds the registry lock (slow path) OR has ST-unique access to a cached stream
/// (pointer-keyed fast path). Pure stream mutation (no membrane/registry), so identical bytes.
///
/// # Safety
/// `s` must be uniquely borrowed for this call (registry lock held, or ST cache-gated).
unsafe fn fgets_fill_stream(s: &mut StdioStream, dst: &mut [u8]) -> (usize, bool) {
    let max = dst.len();
    let mut written = 0usize;
    let mut had_error = false;
    while written < max {
        let (n, outcome) = s.read_into_slice(b'\n', &mut dst[written..]);
        written += n;
        match outcome {
            ReadUntil::Found => break,
            ReadUntil::Eof => {
                if s.is_error() {
                    had_error = true;
                }
                break;
            }
            ReadUntil::NeedRefill => {
                if written >= max {
                    break;
                }
                if s.is_eof() || s.is_error() {
                    if s.is_error() {
                        had_error = true;
                    }
                    break;
                }
                if s.buffer_capacity() == 0 {
                    // Unbuffered fd stream: read a byte directly.
                    let mut b = [0u8; 1];
                    let fd = s.fd();
                    let rc = unsafe { sys_read_fd(fd, b.as_mut_ptr().cast(), 1) };
                    if rc > 0 {
                        s.set_offset(s.offset().saturating_add(1));
                        dst[written] = b[0];
                        written += 1;
                        if b[0] == b'\n' {
                            break;
                        }
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
                } else if unsafe { refill_stream(s) } <= 0 {
                    if s.is_error() {
                        had_error = true;
                    }
                    break;
                }
            }
        }
    }
    (written, had_error)
}

/// Cached-stream ASCII wide-line reader used by `fgetws`. A cache hit is the
/// same ST/non-cookie/non-mem fd-stream proof used by `fgets`; the stream method
/// only consumes when buffered bytes are all ASCII through newline or destination
/// capacity, otherwise it leaves the stream untouched for `fgetwc`.
pub(crate) unsafe fn read_cached_ascii_line_wide(
    stream: *mut c_void,
    dst: &mut [u32],
) -> Option<(usize, bool)> {
    let p = write_cache_lookup_by_stream(stream)?;
    // SAFETY: ST-gated + generation-valid cache hit gives unique stream access.
    let s = unsafe { &mut *p };
    match s.read_ascii_line_into_wide(dst) {
        Some((n, ReadUntil::Found)) => Some((n, false)),
        Some((n, ReadUntil::NeedRefill)) if n == dst.len() => Some((n, false)),
        Some((0, ReadUntil::NeedRefill)) => {
            if s.buffer_capacity() == 0 {
                return None;
            }
            if unsafe { refill_stream(s) } <= 0 {
                return Some((0, s.is_error()));
            }
            match s.read_ascii_line_into_wide(dst) {
                Some((n, ReadUntil::Found)) => Some((n, false)),
                Some((n, ReadUntil::NeedRefill)) if n == dst.len() => Some((n, false)),
                Some((0, ReadUntil::Eof)) => Some((0, s.is_error())),
                _ => None,
            }
        }
        Some((0, ReadUntil::Eof)) => Some((0, s.is_error())),
        _ => None,
    }
}

pub unsafe extern "C" fn fgets(buf: *mut c_char, size: c_int, stream: *mut c_void) -> *mut c_char {
    if buf.is_null() || size <= 0 {
        return std::ptr::null_mut();
    }
    if size == 1 {
        unsafe { *buf = 0 };
        return buf;
    }
    // ST fast path: a cache hit is a non-cookie non-mem fd stream, so the is_mem_backed
    // sync is skipped and read_into_slice runs directly — skipping canonical_stream_id's
    // native lock + registry_contains_stream + registry().lock() + decide/observe per line
    // (hot when reading lines from a fopen'd file). Byte-identical (same bulk fill loop).
    if let Some(p) = write_cache_lookup_by_stream(stream) {
        let max = (size - 1) as usize;
        if max == 0 {
            unsafe { *buf = 0 };
            return buf;
        }
        // SAFETY: ST-gated + gen-valid ⇒ unique &mut; `buf` valid for `size` bytes.
        let dst = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, max) };
        let (written, had_error) = unsafe { fgets_fill_stream(&mut *p, dst) };
        if (written == 0 && max > 0) || had_error {
            return std::ptr::null_mut();
        }
        unsafe { *buf.add(written) = 0 };
        return buf;
    }
    let id = canonical_stream_id(stream);
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
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
    if s.is_mem_backed() {
        sync_and_unregister_fast_fixed_mem_read(id, s);
    } else {
        // Cache this non-cookie, non-mem fd stream so subsequent fgets/fgetc/fread hit the
        // pointer-keyed fast path — a pure `fgets` loop (read a file line by line) otherwise
        // never populates the cache and pays the per-line locks forever. Mirrors fgetc/fread.
        write_cache_store(id, s as *mut StdioStream);
    }

    // Fill the destination under the SINGLE registry lock + policy decision
    // taken above, scanning the stream buffer for '\n' with read_into_slice
    // instead of calling buffered_read(1) — which allocates a 1-byte Vec — once
    // per character. read_into_slice writes straight into the C buffer (zero
    // heap traffic); the ABI layer owns descriptor refill since the membrane
    // policy and sys_read_fd live here.
    let dst = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, max) };
    let (written, had_error) = unsafe { fgets_fill_stream(s, dst) };

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

    // Single-threaded inline fast path: scan once, append to the cached Full-buffered fd
    // stream if it all fits (skipping membrane + registry lock + HashMap lookup). Keyed by
    // the raw FILE* pointer so a repeated-write loop skips `canonical_stream_id` and its
    // `native_stdio_fd_for_ptr` lock entirely (the dominant ST fast-path cost for non-std
    // fopen'd streams). On any miss (not cached / not Full / would flush) fall through to
    // the existing paths, computing `id` lazily below.
    if let Some(p) = write_cache_lookup_by_stream(stream) {
        let (len, _) = unsafe { scan_c_str_len(s, None) };
        let bytes = unsafe { std::slice::from_raw_parts(s as *const u8, len) };
        // SAFETY: single-threaded (lookup-gated) ⇒ unique &mut; gen-valid ⇒ not moved.
        if unsafe { (*p).fast_write(bytes) } {
            return 0;
        }
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
        // Host delegation path - not available in standalone mode
        #[cfg(not(feature = "standalone"))]
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

    // Single-threaded inline fast path: fill the whole request from the cached fd stream's
    // buffer if it's all there (skip membrane + lock + lookup + host check). Pointer-keyed
    // so a hit also skips `canonical_stream_id`'s native lock; `id` computed lazily on miss.
    {
        let dst = unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, total) };
        if try_fread_fast_by_stream(stream, dst) {
            return nmemb;
        }
    }

    let id = canonical_stream_id(stream);

    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
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
        sync_and_unregister_fast_fixed_mem_read(id, s);
        // Read straight into the caller's buffer — no throwaway Vec per fread.
        let n = s.mem_read_into(&mut dst[..total]);
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(15, total),
            n < total,
        );
        return n.checked_div(size).unwrap_or(0);
    }

    // Cache this non-cookie, non-mem fd stream so subsequent single-threaded reads hit the
    // inline fast path (try_fread_fast / try_fgetc_fast).
    write_cache_store(id, s as *mut StdioStream);

    while read_total < total {
        let n = s.buffered_read_into(&mut dst[read_total..total]);
        if n > 0 {
            read_total += n;
            continue;
        }
        if s.is_error() {
            break;
        }

        // Small remaining request on a buffered stream: refill the read buffer in one
        // block (like glibc / fgetc) instead of a per-call direct fd read — without this,
        // a loop of small `fread`s did one syscall EACH (~131x slower than glibc). The
        // refill (sys_read_fd into a tmp + fill_read_buffer copy) is the same mechanism
        // fgetc uses, so it carries no extra LD_PRELOAD recursion risk. Large requests
        // (>= capacity) keep the direct read below (buffering would just add a copy).
        let cap = s.buffer_capacity();
        if cap > 0 && (total - read_total) < cap && !s.is_eof() {
            let rc = unsafe { refill_stream(s) };
            if rc > 0 {
                continue; // next buffered_read_into serves from the refilled buffer
            }
            break; // EOF (0) or error (<0, flagged on the stream by refill_stream)
        }

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

    let src = unsafe { std::slice::from_raw_parts(ptr as *const u8, total) };

    // Single-threaded inline fast path: append to the cached Full-buffered fd stream if it
    // all fits (skip membrane + lock + lookup). Pointer-keyed so a hit also skips
    // `canonical_stream_id`'s native lock; `id` computed lazily on miss.
    if try_fwrite_fast_by_stream(stream, src) {
        return nmemb;
    }

    let id = canonical_stream_id(stream);

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
        // Host delegation path - not available in standalone mode
        #[cfg(not(feature = "standalone"))]
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
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
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
        if let Some(cursor) = fast_fixed_mem_read(id) {
            let Some(new_pos) = cursor.seek(offset, whence) else {
                unsafe { set_abi_errno(errno::EINVAL) };
                runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
                return -1;
            };
            let _ = s.mem_seek(new_pos as i64, libc::SEEK_SET);
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, false);
            return 0;
        }
        unsafe {
            sync_memstream_to_caller(id, s);
            sync_fmemopen_full(id, s);
            crate::wchar_abi::sync_open_wmemstream_to_caller(id, s);
        }
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
    // ST fast path: a cache hit is a non-mem fd stream whose offset is tracked inline;
    // sync_fast_fixed_mem_read_to_stream is a no-op and decide()==Allow in strict, so
    // returning `offset()` directly is byte-identical (matches the existing cache-hit
    // fast paths that skip decide). Skips the 3 per-call locks.
    if let Some(p) = write_cache_lookup_by_stream(stream) {
        // SAFETY: ST-gated + gen-valid ⇒ pointer live, shared read only.
        return unsafe { (*p).offset() } as c_long;
    }
    let id = canonical_stream_id(stream);
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
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

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return -1;
    };

    let _ = sync_fast_fixed_mem_read_to_stream(id, s);
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
        if let Some(cursor) = fast_fixed_mem_read(id) {
            cursor.eof.store(false, Ordering::Release);
        }
    }
}

// ---------------------------------------------------------------------------
// feof / ferror / clearerr / ungetc / fileno
// ---------------------------------------------------------------------------

/// POSIX `feof`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feof(stream: *mut c_void) -> c_int {
    // Single-threaded inline fast path: the pointer-keyed write cache only ever holds
    // non-cookie, non-mem fd streams, so `sync_fast_fixed_mem_read_to_stream` is a no-op
    // for a cached stream (fast_fixed_mem_read(id) == None) — reading `is_eof()` directly
    // is byte-identical to the slow path, skipping canonical_stream_id's native lock +
    // registry_contains_stream + registry().lock() (3 locks/call, hot in `while(!feof)`).
    if let Some(p) = write_cache_lookup_by_stream(stream) {
        // SAFETY: ST-gated (unique access) + gen-valid ⇒ pointer live, shared read only.
        return if unsafe { (*p).is_eof() } { 1 } else { 0 };
    }
    let id = canonical_stream_id(stream);
    if id == 0 {
        return 0;
    }
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
    if !registry_contains_stream(id)
        && let Some(host_feof) = unsafe { host_feof_fn() }
    {
        return unsafe { host_feof(stream) };
    }
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        let _ = sync_fast_fixed_mem_read_to_stream(id, s);
        if s.is_eof() { 1 } else { 0 }
    } else {
        0
    }
}

/// POSIX `ferror`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ferror(stream: *mut c_void) -> c_int {
    // Single-threaded inline fast path (see feof): cached => non-mem fd stream => read
    // `is_error()` directly, skipping the 3 per-call locks. Byte-identical.
    if let Some(p) = write_cache_lookup_by_stream(stream) {
        // SAFETY: ST-gated + gen-valid ⇒ pointer live, shared read only.
        return if unsafe { (*p).is_error() } { 1 } else { 0 };
    }
    let id = canonical_stream_id(stream);
    if id == 0 {
        return 0;
    }
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
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
    // ST fast path: a cache hit is a non-mem fd stream (fast_fixed_mem_read(id)==None), so
    // the slow path reduces to `s.clear_err()` — do it directly, skipping the 3 per-call
    // locks. Byte-identical. Mutating, but ST-gated ⇒ unique access.
    if let Some(p) = write_cache_lookup_by_stream(stream) {
        // SAFETY: ST-gated + gen-valid ⇒ unique &mut for this call.
        unsafe { (*p).clear_err() };
        return;
    }
    let id = canonical_stream_id(stream);
    if id == 0 {
        return;
    }
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
    if !registry_contains_stream(id) {
        if let Some(host_clearerr) = unsafe { host_clearerr_fn() } {
            unsafe { host_clearerr(stream) };
        }
        return;
    }
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        s.clear_err();
        if let Some(cursor) = fast_fixed_mem_read(id) {
            cursor.eof.store(false, Ordering::Release);
        }
    }
}

/// POSIX `ungetc`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ungetc(c: c_int, stream: *mut c_void) -> c_int {
    if c == libc::EOF {
        return libc::EOF;
    }
    // ST fast path: a cache hit is a non-cookie non-mem fd stream, so the slow path's
    // sync_and_unregister_fast_fixed_mem_read is a no-op (fast_fixed_mem_read(id)==None) —
    // reduce to s.ungetc() directly, skipping 4 per-call locks (native + registry_contains +
    // registry + fast_fixed_mem_reads). Byte-identical; mutating but ST-gated ⇒ unique &mut.
    // The common ungetc-after-fgetc parser pattern leaves the stream cached, so this hits.
    if let Some(p) = write_cache_lookup_by_stream(stream) {
        // SAFETY: ST-gated + gen-valid ⇒ unique &mut for this call.
        return if unsafe { (*p).ungetc(c as u8) } {
            c
        } else {
            libc::EOF
        };
    }
    let id = canonical_stream_id(stream);
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
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
        sync_and_unregister_fast_fixed_mem_read(id, s);
        if s.ungetc(c as u8) { c } else { libc::EOF }
    } else {
        libc::EOF
    }
}

/// POSIX `fileno`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fileno(stream: *mut c_void) -> c_int {
    // ST fast path: a cache hit is a non-cookie non-mem fd stream, so `is_mem_backed()`
    // is false and the slow path returns `s.fd()` — read it directly, skipping the 3
    // per-call locks (native + registry_contains + registry). Byte-identical. (feof A/B:
    // 3-lock elision = ~16ns/call.)
    if let Some(p) = write_cache_lookup_by_stream(stream) {
        // SAFETY: ST-gated + gen-valid ⇒ pointer live, shared read only.
        return unsafe { (*p).fd() };
    }
    let id = canonical_stream_id(stream);
    if id == 0 {
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
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
        #[cfg(not(feature = "standalone"))]
        if host_stream_io_started(id) {
            unsafe { set_abi_errno(errno::EINVAL) };
            return -1;
        }
        // Host delegation path - not available in standalone mode
        #[cfg(not(feature = "standalone"))]
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

    // Single-threaded inline fast path: append body + '\n' to the cached Full-buffered
    // stdout in one shot (skip membrane + the TWO write_bytes locks). Miss → full path.
    {
        let stdout_id = canonical_stream_id(active_stdout_stream());
        if let Some(p) = write_cache_lookup(stdout_id) {
            let (len, _) = unsafe { scan_c_str_len(s, None) };
            let bytes = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), len) };
            // SAFETY: single-threaded (lookup-gated) ⇒ unique &mut; gen-valid ⇒ not moved.
            if unsafe { (*p).fast_puts(bytes) } {
                return 0;
            }
        }
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

    // Get current errno and map to message via the SHARED renderer (the
    // complete, glibc-exact strerrordesc_np table, including "Unknown error <N>"
    // for unknown codes). The previous inline table covered only ~22 common
    // errnos and rendered everything else — EAGAIN, the high/socket errnos, and
    // truly unknown codes — as a numberless "Unknown error".
    let err = unsafe { *super::errno_abi::__errno_location() };
    let (rendered, _) = crate::string_abi::rendered_strerror_message(err);
    let msg: &[u8] = rendered.as_bytes();

    if !s.is_null() {
        let prefix = unsafe { bounded_c_str_bytes(s) }.unwrap_or(&[]);
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
                            $buf[_idx] = unsafe { $args.next_arg::<u64>() };
                            _idx += 1;
                        }
                    }
                    ValueArgKind::Fp => {
                        if _idx < $extract_count {
                            $buf[_idx] = unsafe { $args.next_arg::<f64>() }.to_bits();
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
                        let raw = unsafe { $args.next_arg::<core::ffi::c_int>() };
                        $buf[_idx] = (raw as i64) as u64;
                        _idx += 1;
                    }
                    if spec.precision.uses_arg() && _idx < $extract_count {
                        let raw = unsafe { $args.next_arg::<core::ffi::c_int>() };
                        $buf[_idx] = (raw as i64) as u64;
                        _idx += 1;
                    }
                    if spec.value_arg_is_float() && _idx < $extract_count {
                        $buf[_idx] = unsafe { $args.next_arg::<f64>() }.to_bits();
                        _idx += 1;
                    } else if spec.value_arg_is_gp() && _idx < $extract_count {
                        $buf[_idx] = unsafe { $args.next_arg::<u64>() };
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
/// Thread-local reuse pool for the printf output buffer. Every copy-out printf
/// (snprintf/sprintf/fprintf/printf/dprintf + v*) builds its result in a fresh
/// `Vec` then discards it after copying to the destination — one alloc+free per
/// call. The pool keeps a single reusable buffer so the steady-state per-call
/// allocation is eliminated. Correctness is independent of pooling: the buffer
/// is cleared on take (no stale bytes), [`ScratchVec`]'s `Drop` returns it only
/// after all borrows end (borrow-checker enforced), and a missed return merely
/// falls back to a fresh allocation.
mod printf_out_pool {
    use std::cell::Cell;
    thread_local! {
        static POOL: Cell<Option<Vec<u8>>> = const { Cell::new(None) };
    }
    pub(super) fn take() -> Vec<u8> {
        POOL.with(|p| p.take()).map_or_else(
            || Vec::with_capacity(256),
            |mut v| {
                v.clear();
                v
            },
        )
    }
    pub(super) fn give(v: Vec<u8>) {
        POOL.with(|p| {
            // Single slot: keep whichever buffer has the larger capacity.
            let keep = match p.take() {
                Some(existing) if existing.capacity() >= v.capacity() => existing,
                _ => v,
            };
            p.set(Some(keep));
        });
    }
}

/// A printf output buffer borrowed from [`printf_out_pool`]. Derefs to the inner
/// `Vec<u8>` so existing callers that only read it (`.len()`, `.as_ptr()`,
/// `&buf[..]`) are unaffected; on `Drop` the allocation returns to the pool for
/// the next call. Callers that need to take ownership (e.g. `asprintf`) use
/// [`ScratchVec::into_vec`], which removes the buffer from the pooling path.
pub(crate) struct ScratchVec(Option<Vec<u8>>);

impl ScratchVec {
    fn new(v: Vec<u8>) -> Self {
        ScratchVec(Some(v))
    }
    /// Take ownership of the underlying `Vec`, opting this buffer out of the
    /// pool (its `Drop` will then be a no-op).
    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        self.0.take().unwrap_or_default()
    }
}

impl std::ops::Deref for ScratchVec {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        self.0.as_ref().expect("ScratchVec accessed after into_vec")
    }
}

impl Drop for ScratchVec {
    fn drop(&mut self) {
        if let Some(v) = self.0.take() {
            printf_out_pool::give(v);
        }
    }
}

///
/// Narrow entry point: `%ls` precision/width are BYTE counts (C99 §7.19.6.1).
pub(crate) unsafe fn render_printf(fmt: &[u8], args: *const u64, max_args: usize) -> Vec<u8> {
    unsafe { render_printf_impl(fmt, args, max_args, false) }
}

/// Wide entry point for the `wprintf`/`swprintf` family. The returned bytes are
/// UTF-8 that the caller decodes back to `wchar_t`; for wide-stream output the
/// `%ls` precision and field width count WIDE CHARACTERS (C standard wide
/// printf), not bytes, so the multibyte truncation/padding is computed in
/// wide-character units here.
pub(crate) unsafe fn render_wprintf(
    segments: &frankenlibc_core::stdio::printf::FormatSegments<'_>,
    args: *const u64,
    max_args: usize,
) -> ScratchVec {
    // Callers (wprintf/swprintf family) already parsed the format for argument
    // counting/extraction; render the pre-parsed segments rather than re-parsing.
    // Return the pooled `ScratchVec` (not `.into_vec()`) so the output buffer
    // returns to the TLS pool on drop — every wide-printf caller below only reads
    // it by reference, so keeping it pooled saves a 256-byte alloc/free per call
    // (the narrow snprintf path already pools; this brings the wide family to parity).
    unsafe { render_segments(segments, args, max_args, true) }
}

unsafe fn render_printf_impl(
    fmt: &[u8],
    args: *const u64,
    max_args: usize,
    wide_output: bool,
) -> Vec<u8> {
    // Parse once here; render_segments does the work, so printf-family callers
    // that already parsed the format (snprintf et al. parse it for arg counting)
    // can call render_segments directly and skip this redundant second parse.
    let segments = parse_format_string(fmt);
    unsafe { render_segments(&segments, args, max_args, wide_output).into_vec() }
}

/// Render already-parsed `segments` into a fresh buffer. Split out from
/// [`render_printf_impl`] so the printf-family entry points can reuse the
/// `FormatSegments` they parsed for argument counting instead of re-parsing the
/// format string a second time on every call.
pub(crate) unsafe fn render_segments(
    segments: &frankenlibc_core::stdio::printf::FormatSegments<'_>,
    args: *const u64,
    max_args: usize,
    wide_output: bool,
) -> ScratchVec {
    let mut buf = printf_out_pool::take();
    let uses_positional = core_positional_printf_arg_plan(segments).is_some();
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

    for seg in segments.iter() {
        match seg {
            FormatSegment::Literal(lit) => buf.extend_from_slice(lit),
            FormatSegment::Percent => buf.push(b'%'),
            FormatSegment::Spec(spec) => {
                // Resolve width from args if needed.
                let mut resolved_spec = *spec;
                if spec.width.uses_arg() {
                    let width_position = if uses_positional {
                        spec.width.position()
                    } else {
                        None
                    };
                    if let Some(raw_width) = read_arg(width_position, &mut arg_idx) {
                        let w = (raw_width as core::ffi::c_int) as i64;
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
                        let p = (raw_precision as core::ffi::c_int) as i64;
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
                    // %m == strerror(errno). Use the shared renderer directly:
                    // it yields glibc's "Unknown error <N>" for unknown codes
                    // (the previous strerror_r path returned EINVAL for those
                    // and fell back to a numberless, width/precision-ignoring
                    // "Unknown error").
                    let e = unsafe { *crate::errno_abi::__errno_location() };
                    let (msg, _) = crate::string_abi::rendered_strerror_message(e);
                    format_str(msg.as_bytes(), &resolved_spec, &mut buf);
                } else if resolved_spec.stores_count() {
                    // %n: store count of units written so far. For narrow
                    // printf that is bytes; for wide printf (swprintf/wprintf/…)
                    // the C standard counts WIDE CHARACTERS, not the UTF-8 bytes
                    // of fl's internal accumulator — so count Unicode scalar
                    // values (every non-continuation byte begins one).
                    // Respects length modifier: %hhn→i8, %hn→i16,
                    // %n→i32, %ln→i64, %lln→i64, %zn→isize, %jn→i64.
                    if let Some(raw_ptr) = read_arg(value_position, &mut arg_idx) {
                        let ptr_val = raw_ptr as usize;
                        if ptr_val != 0 {
                            let count = if wide_output {
                                buf.iter().filter(|&&b| (b & 0xC0) != 0x80).count()
                            } else {
                                buf.len()
                            };
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
                            // glibc substitutes "(null)" for a NULL `%s`/`%ls`
                            // arg, but ONLY when the precision is unspecified or
                            // at least 6 (the length of "(null)"); a smaller
                            // precision yields the empty string rather than a
                            // truncated "(nu". (fl previously truncated it.)
                            let null_str: &[u8] = match resolved_spec.precision {
                                Precision::Fixed(p) if p < b"(null)".len() => b"",
                                _ => b"(null)",
                            };
                            format_str(null_str, &resolved_spec, &mut buf);
                        } else if matches!(resolved_spec.length, LengthMod::L) {
                            // `%ls`: the argument is a `wchar_t*`, NOT a `char*`.
                            // Reading it narrow yields garbage (a 4-byte wchar is
                            // seen as one byte + a NUL).
                            let mut width_spec = resolved_spec;
                            width_spec.precision = Precision::None;
                            if wide_output {
                                // Wide printf (wprintf/swprintf): precision and
                                // field width count WIDE CHARACTERS. Truncate by
                                // wide-char count before encoding, then inflate the
                                // byte width by the multibyte overhead so the byte
                                // padding `format_str` applies lands on wide-column
                                // boundaries after the caller decodes back to wide.
                                let limit = match resolved_spec.precision {
                                    Precision::Fixed(n) => Some(n),
                                    _ => None,
                                };
                                let (utf8, wide_count) =
                                    unsafe { wide_cstr_to_utf8(ptr as *const u32, limit) };
                                if let Width::Fixed(w) = width_spec.width {
                                    let extra = utf8.len().saturating_sub(wide_count);
                                    width_spec.width = Width::Fixed(w + extra);
                                }
                                format_str(&utf8, &width_spec, &mut buf);
                            } else {
                                // Narrow printf: precision and field width are BYTE
                                // counts on the multibyte output (C99 §7.19.6.1).
                                // Convert the whole string, cap bytes without
                                // splitting a multibyte char, pad by bytes.
                                let (mut utf8, _) =
                                    unsafe { wide_cstr_to_utf8(ptr as *const u32, None) };
                                if let Precision::Fixed(p) = resolved_spec.precision {
                                    utf8.truncate(utf8_byte_limit(&utf8, p));
                                }
                                format_str(&utf8, &width_spec, &mut buf);
                            }
                        } else if wide_output {
                            // Wide printf narrow `%s`: the `char*` multibyte content
                            // is converted to wide characters, and precision/width
                            // count WIDE CHARACTERS, not bytes (C99). Take the first
                            // `precision` wide chars (never splitting a multibyte
                            // char) and inflate the byte width by the multibyte
                            // overhead so `format_str`'s byte padding lands on
                            // wide-column boundaries after the caller decodes back.
                            let s_bytes = unsafe { c_str_bytes(ptr as *const c_char) };
                            let limit = match resolved_spec.precision {
                                Precision::Fixed(n) => Some(n),
                                _ => None,
                            };
                            let (utf8, wide_count) = utf8_take_chars(s_bytes, limit);
                            let mut width_spec = resolved_spec;
                            width_spec.precision = Precision::None;
                            if let Width::Fixed(w) = width_spec.width {
                                let extra = utf8.len().saturating_sub(wide_count);
                                width_spec.width = Width::Fixed(w + extra);
                            }
                            format_str(&utf8, &width_spec, &mut buf);
                        } else {
                            let s_bytes = unsafe { c_str_bytes(ptr as *const c_char) };
                            format_str(s_bytes, &resolved_spec, &mut buf);
                        }
                    }
                } else if resolved_spec.conversion == b'c'
                    && matches!(resolved_spec.length, LengthMod::L)
                {
                    // `%lc` / `%C`: the argument is a `wint_t` wide character, not
                    // a byte. The default char path would emit only its low byte
                    // (garbage for non-ASCII); instead UTF-8-encode the code point.
                    if let Some(raw) = read_arg(value_position, &mut arg_idx) {
                        let mut utf8 = Vec::new();
                        if let Some(c) = char::from_u32(raw as u32) {
                            let mut b = [0u8; 4];
                            utf8.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
                        }
                        // Precision is ignored for %c. Narrow printf: width is a
                        // BYTE field — the multibyte char's byte length counts
                        // toward it (no inflation). Wide printf: width counts WIDE
                        // characters (one here), so inflate the byte width by the
                        // multibyte overhead to keep padding on the wide boundary.
                        let mut width_spec = resolved_spec;
                        width_spec.precision = Precision::None;
                        if wide_output && let Width::Fixed(w) = width_spec.width {
                            let extra = utf8.len().saturating_sub(1);
                            width_spec.width = Width::Fixed(w + extra);
                        }
                        format_str(&utf8, &width_spec, &mut buf);
                    }
                } else if let Some(raw) = read_arg(value_position, &mut arg_idx) {
                    let _ = resolved_spec.render_value_arg(raw, &mut buf);
                }
            }
        }
    }
    ScratchVec::new(buf)
}

/// Returns the bytes a printf-family call must emit, taking the bare-"%s" fast
/// path when possible: for an exact, non-NULL `%s` the caller's NUL-terminated
/// string is returned directly (no render, no intermediate buffer); otherwise
/// the format is rendered into `*hold` (kept alive by the caller) and that
/// buffer is returned. Output is identical to rendering "%s" (which just copies
/// the string); a NULL argument falls through to render so glibc's "(null)" is
/// still produced.
///
/// # Safety
/// `args` must point to at least `extract_count` extracted argument slots, and a
/// bare-`%s` argument must be a valid NUL-terminated string per the C contract.
unsafe fn bare_s_or_render<'a>(
    fmt_bytes: &'a [u8],
    segments: &frankenlibc_core::stdio::printf::FormatSegments<'_>,
    args: *const u64,
    extract_count: usize,
    hold: &'a mut Option<ScratchVec>,
) -> &'a [u8] {
    if let Some(DirectPrintfPayload::String(bytes)) =
        unsafe { direct_printf_string_payload(fmt_bytes, args, extract_count) }
    {
        return bytes;
    }
    // No '%' anywhere: no conversions and no `%%` escapes, so the format string
    // is emitted verbatim (ubiquitous fixed-message / banner output). Return it
    // directly, skipping the parse-into-segments and the render buffer.
    if !fmt_bytes.contains(&b'%') {
        return fmt_bytes;
    }
    *hold = Some(unsafe { render_segments(segments, args, extract_count, false) });
    hold.as_deref().unwrap()
}

#[derive(Clone, Copy)]
enum DirectPrintfPayload<'a> {
    String(&'a [u8]),
    StringNewline(&'a [u8]),
}

#[inline]
unsafe fn exact_direct_s_format(format: *const c_char) -> Option<bool> {
    let f = format.cast::<u8>();
    if unsafe { *f } != b'%' || unsafe { *f.add(1) } != b's' {
        return None;
    }
    match unsafe { *f.add(2) } {
        0 => Some(false),
        b'\n' if unsafe { *f.add(3) } == 0 => Some(true),
        _ => None,
    }
}

#[inline]
unsafe fn exact_direct_c_format(format: *const c_char) -> bool {
    let f = format.cast::<u8>();
    unsafe { *f == b'%' && *f.add(1) == b'c' && *f.add(2) == 0 }
}

#[inline]
unsafe fn exact_direct_u_format(format: *const c_char) -> bool {
    let f = format.cast::<u8>();
    // SAFETY: `format` is non-null and C's printf contract requires a
    // NUL-terminated format string, so these three bytes are readable.
    unsafe { *f == b'%' && *f.add(1) == b'u' && *f.add(2) == 0 }
}

#[inline]
unsafe fn exact_direct_p_format(format: *const c_char) -> bool {
    let f = format.cast::<u8>();
    // SAFETY: `format` is non-null and C's printf contract requires a
    // NUL-terminated format string, so these three bytes are readable.
    unsafe { *f == b'%' && *f.add(1) == b'p' && *f.add(2) == 0 }
}

fn read_only_mappings() -> &'static [(usize, usize)] {
    READ_ONLY_MAPPINGS
        .get_or_init(|| {
            let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
                return Vec::new();
            };
            maps.lines()
                .filter_map(|line| {
                    let mut fields = line.split_whitespace();
                    let range = fields.next()?;
                    let perms = fields.next()?;
                    let mut endpoints = range.split('-');
                    let start = usize::from_str_radix(endpoints.next()?, 16).ok()?;
                    let end = usize::from_str_radix(endpoints.next()?, 16).ok()?;
                    let bytes = perms.as_bytes();
                    if bytes.first() == Some(&b'r') && bytes.get(1) != Some(&b'w') {
                        Some((start, end))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .as_slice()
}

#[inline]
fn literal_format_cache_entry(format: *const c_char) -> &'static LiteralFormatCacheEntry {
    let idx = ((format as usize) >> 4) & (LITERAL_FORMAT_CACHE_SIZE - 1);
    &LITERAL_FORMAT_CACHE[idx]
}

#[inline]
fn lookup_literal_format_len(format: *const c_char) -> Option<usize> {
    let ptr = format as usize;
    let entry = literal_format_cache_entry(format);
    if entry.key.load(Ordering::Acquire) != ptr {
        return None;
    }
    let len = entry.len.load(Ordering::Acquire);
    if entry.key.load(Ordering::Acquire) == ptr {
        Some(len)
    } else {
        None
    }
}

#[inline]
fn cache_literal_format_len(format: *const c_char, len: usize) {
    let ptr = format as usize;
    let Some(end) = ptr.checked_add(len.saturating_add(1)) else {
        return;
    };
    if !read_only_mappings()
        .iter()
        .any(|&(start, stop)| ptr >= start && end <= stop)
    {
        return;
    }

    let entry = literal_format_cache_entry(format);
    entry.key.store(0, Ordering::Release);
    entry.len.store(len, Ordering::Release);
    entry.key.store(ptr, Ordering::Release);
}

#[inline]
unsafe fn strict_literal_format_len(format: *const c_char) -> Option<usize> {
    if let Some(len) = lookup_literal_format_len(format) {
        return Some(len);
    }

    let f = format.cast::<u8>();
    let mut len = 0usize;
    loop {
        match unsafe { *f.add(len) } {
            0 => {
                cache_literal_format_len(format, len);
                return Some(len);
            }
            b'%' => return None,
            _ => len = len.saturating_add(1),
        }
    }
}

/// Return the zero-copy payload for exact non-NULL `%s` and `%s\n` formats.
///
/// The newline form is intentionally represented as two slices instead of
/// materializing `string + "\n"`; callers decide whether their destination can
/// preserve the old single-buffer failure semantics before using it.
unsafe fn direct_printf_string_payload<'a>(
    fmt_bytes: &[u8],
    args: *const u64,
    extract_count: usize,
) -> Option<DirectPrintfPayload<'a>> {
    if extract_count < 1 || !(fmt_bytes == b"%s" || fmt_bytes == b"%s\n") {
        return None;
    }
    let p = unsafe { *args } as *const u8;
    if p.is_null() {
        return None;
    }
    let len = unsafe { c_str_bytes(p as *const c_char) }.len();
    // SAFETY: the %s contract guarantees a NUL-terminated string that remains
    // valid for the duration of the printf-family call.
    let bytes = unsafe { std::slice::from_raw_parts(p, len) };
    if fmt_bytes == b"%s\n" {
        Some(DirectPrintfPayload::StringNewline(bytes))
    } else {
        Some(DirectPrintfPayload::String(bytes))
    }
}

unsafe fn copy_direct_printf_payload(
    dst: *mut c_char,
    src: &[u8],
    append_newline: bool,
    copy_len: usize,
) {
    let string_copy = copy_len.min(src.len());
    if string_copy > 0 {
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst.cast::<u8>(), string_copy) };
    }
    if append_newline && copy_len > src.len() {
        unsafe { *dst.add(src.len()) = b'\n' as c_char };
    }
    unsafe { *dst.add(copy_len) = 0 };
}

unsafe fn direct_snprintf_s(
    str_buf: *mut c_char,
    size: usize,
    arg: *const c_char,
    append_newline: bool,
    mode: SafetyLevel,
    decision: RuntimeDecision,
) -> c_int {
    let src = if arg.is_null() {
        b"(null)"
    } else {
        unsafe { c_str_bytes(arg) }
    };
    let total_len = src.len().saturating_add(usize::from(append_newline));
    let mut copy_len = if size > 0 { total_len.min(size - 1) } else { 0 };
    let mut adverse = false;
    let mut has_room = size > 0 && !str_buf.is_null();

    if repair_enabled(mode.heals_enabled(), decision.action)
        && let Some(bound) = known_remaining(str_buf as usize)
    {
        let safe_size = size.min(bound);
        if safe_size == 0 {
            has_room = false;
            if size > 0 {
                adverse = true;
                global_healing_policy().record(&HealingAction::ClampSize {
                    requested: size,
                    clamped: 0,
                });
            }
        } else {
            let max_payload = safe_size.saturating_sub(1);
            if copy_len > max_payload {
                copy_len = max_payload;
                adverse = true;
                global_healing_policy().record(&HealingAction::TruncateWithNull {
                    requested: total_len.min(size.saturating_sub(1)).saturating_add(1),
                    truncated: copy_len,
                });
            }
        }
    }

    if has_room {
        unsafe { copy_direct_printf_payload(str_buf, src, append_newline, copy_len) };
    }

    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(15, total_len),
        adverse,
    );
    printf_result_to_c_int(total_len)
}

unsafe fn strict_direct_snprintf_s(
    str_buf: *mut c_char,
    size: usize,
    arg: *const c_char,
    append_newline: bool,
) -> c_int {
    // Length the argument with the page-safe SWAR/SIMD `scan_c_string` (the exact
    // NUL scanner the deployed `strlen` ABI uses — NO membrane `known_remaining`),
    // then bulk-copy with `memcpy`. The previous fused scan+copy loop paid a
    // per-byte bound branch + scalar load/store. IN-PROCESS A/B (same worker, same
    // run; snprintf_s_strict_ab_bench): for the bare "%s" copy kernel this is
    // 2.6x faster than the byte loop at 38B (7.85 vs 20.5ns) and 5.6x at 200B
    // (16.3 vs 91.7ns), and beats host glibc's snprintf at every size (4x@38B,
    // 2x@200B); tiny <=8B strings cost a few ns more than the byte loop (SIMD
    // prologue) but still beat glibc ~3x. Crucially call `scan_c_string` DIRECTLY,
    // NOT `c_str_bytes` (which routes through `known_remaining`, a membrane
    // object-size lookup that is ~5x the whole copy — that path was a measured
    // regression). Output is byte-for-byte identical: truncation, newline, and
    // NULL ("(null)") edge cases preserved.
    let src: &[u8] = if arg.is_null() {
        b"(null)"
    } else {
        let (len, _) = unsafe { super::string_abi::scan_c_string(arg, None) };
        // SAFETY: scan_c_string scanned to the first NUL, so `len` bytes are readable.
        unsafe { std::slice::from_raw_parts(arg.cast::<u8>(), len) }
    };
    let len = src.len();

    if size == 0 || str_buf.is_null() {
        return printf_result_to_c_int(len.saturating_add(usize::from(append_newline)));
    }

    let dst = str_buf.cast::<u8>();
    let copy_limit = size - 1;
    let string_copy = len.min(copy_limit);
    if string_copy > 0 {
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst, string_copy) };
    }

    let total_len = len.saturating_add(usize::from(append_newline));
    if append_newline && len < copy_limit {
        unsafe { *dst.add(len) = b'\n' };
    }
    unsafe { *dst.add(total_len.min(copy_limit)) = 0 };
    printf_result_to_c_int(total_len)
}

#[inline]
unsafe fn strict_direct_snprintf_c(str_buf: *mut c_char, size: usize, arg: c_int) -> c_int {
    if size > 0 && !str_buf.is_null() {
        if size > 1 {
            unsafe { *str_buf = (arg as u8) as c_char };
            unsafe { *str_buf.add(1) = 0 };
        } else {
            unsafe { *str_buf = 0 };
        }
    }
    1
}

#[inline]
unsafe fn strict_direct_snprintf_u(str_buf: *mut c_char, size: usize, arg: c_uint) -> c_int {
    // A promoted unsigned int has at most ten decimal digits. Build backwards
    // into a fixed stack buffer, then apply snprintf's full-length/truncation
    // contract directly without format parsing or a heap-backed render buffer.
    let mut rendered = [0u8; 10];
    let mut value = arg;
    let mut start = rendered.len();
    loop {
        start -= 1;
        rendered[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let len = rendered.len() - start;

    if size > 0 && !str_buf.is_null() {
        let copy_len = len.min(size - 1);
        if copy_len > 0 {
            // SAFETY: `copy_len <= size - 1` is writable by snprintf's caller,
            // and the local source contains exactly `len` initialized bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    rendered.as_ptr().add(start),
                    str_buf.cast::<u8>(),
                    copy_len,
                )
            };
        }
        // SAFETY: `copy_len < size`, so the terminator is in bounds.
        unsafe { *str_buf.add(copy_len) = 0 };
    }
    printf_result_to_c_int(len)
}

#[inline]
unsafe fn strict_direct_snprintf_p(str_buf: *mut c_char, size: usize, arg: *mut c_void) -> c_int {
    let mut rendered = [0u8; 2 + usize::BITS as usize / 4];
    let (start, len) = if arg.is_null() {
        rendered[..5].copy_from_slice(b"(nil)");
        (0, 5)
    } else {
        let mut value = arg as usize;
        let mut pos = rendered.len();
        loop {
            pos -= 1;
            let digit = (value & 0xf) as u8;
            rendered[pos] = if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            };
            value >>= 4;
            if value == 0 {
                break;
            }
        }
        pos -= 2;
        rendered[pos] = b'0';
        rendered[pos + 1] = b'x';
        (pos, rendered.len() - pos)
    };

    if size > 0 && !str_buf.is_null() {
        let copy_len = len.min(size - 1);
        if copy_len > 0 {
            // SAFETY: snprintf's contract provides `size` writable destination
            // bytes; `copy_len <= size - 1` and the local source has `len` bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    rendered.as_ptr().add(start),
                    str_buf.cast::<u8>(),
                    copy_len,
                )
            };
        }
        // SAFETY: `copy_len < size`, so the terminator is within the caller's
        // writable snprintf destination region.
        unsafe { *str_buf.add(copy_len) = 0 };
    }
    printf_result_to_c_int(len)
}

#[inline]
unsafe fn strict_direct_sprintf_c(str_buf: *mut c_char, arg: c_int) -> c_int {
    unsafe { *str_buf = (arg as u8) as c_char };
    unsafe { *str_buf.add(1) = 0 };
    1
}

#[inline]
unsafe fn copy_literal_bytes(dst: *mut c_char, src: *const c_char, len: usize) {
    let dst = dst.cast::<u8>();
    let src = src.cast::<u8>();
    let mut offset = 0usize;
    while offset + 8 <= len {
        let word = unsafe { std::ptr::read_unaligned(src.add(offset).cast::<u64>()) };
        unsafe { std::ptr::write_unaligned(dst.add(offset).cast::<u64>(), word) };
        offset += 8;
    }
    while offset < len {
        unsafe { *dst.add(offset) = *src.add(offset) };
        offset += 1;
    }
}

unsafe fn strict_direct_snprintf_literal(
    str_buf: *mut c_char,
    size: usize,
    format: *const c_char,
    len: usize,
) -> c_int {
    if size > 0 && !str_buf.is_null() {
        let copy_len = len.min(size - 1);
        if copy_len > 0 {
            unsafe { copy_literal_bytes(str_buf, format, copy_len) };
        }
        unsafe { *str_buf.add(copy_len) = 0 };
    }
    printf_result_to_c_int(len)
}

unsafe fn strict_direct_sprintf_literal(
    str_buf: *mut c_char,
    format: *const c_char,
    len: usize,
) -> c_int {
    if len > 0 {
        unsafe { copy_literal_bytes(str_buf, format, len) };
    }
    unsafe { *str_buf.add(len) = 0 };
    printf_result_to_c_int(len)
}

unsafe fn try_write_direct_s_newline_stream(id: usize, payload: &[u8]) -> Option<bool> {
    let total_len = payload.len().saturating_add(1);
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let s = reg.streams.get_mut(&id)?;

    if s.is_mem_backed() {
        let mut written = s.mem_write(payload);
        if written == payload.len() {
            written = written.saturating_add(s.mem_write(b"\n"));
        }
        let adverse = written < total_len;
        if adverse {
            s.set_error();
        }
        return Some(!adverse);
    }

    if !matches!(s.buf_mode(), BufMode::Full) {
        return None;
    }
    let pending = s.pending_flush().len();
    if pending.saturating_add(total_len) > s.buffer_capacity() {
        return None;
    }

    let first = match s.buffer_write(payload) {
        Some(result) if !result.flush_needed => result.buffered,
        _ => {
            s.set_error();
            return Some(false);
        }
    };
    let second = match s.buffer_write(b"\n") {
        Some(result) if !result.flush_needed => result.buffered,
        _ => {
            s.set_error();
            return Some(false);
        }
    };

    let accepted = first.saturating_add(second);
    if accepted == total_len {
        s.set_offset(s.offset().saturating_add(total_len as i64));
        Some(true)
    } else {
        s.set_error();
        Some(false)
    }
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
    if runtime_policy::strict_passthrough_active()
        && let Some(literal_len) = unsafe { strict_literal_format_len(format) }
    {
        return unsafe { strict_direct_snprintf_literal(str_buf, size, format, literal_len) };
    }
    if runtime_policy::strict_passthrough_active()
        && let Some(append_newline) = unsafe { exact_direct_s_format(format) }
    {
        let arg = unsafe { args.next_arg::<*const c_char>() };
        return unsafe { strict_direct_snprintf_s(str_buf, size, arg, append_newline) };
    }
    if runtime_policy::strict_passthrough_active() && unsafe { exact_direct_c_format(format) } {
        let arg = unsafe { args.next_arg::<c_int>() };
        return unsafe { strict_direct_snprintf_c(str_buf, size, arg) };
    }
    if runtime_policy::strict_passthrough_active() && unsafe { exact_direct_u_format(format) } {
        // SAFETY: exact `%u` consumes one promoted `unsigned int` argument.
        let arg = unsafe { args.next_arg::<c_uint>() };
        // SAFETY: snprintf's caller provides `size` writable bytes whenever
        // `size > 0`; the helper bounds every write and appends the terminator.
        return unsafe { strict_direct_snprintf_u(str_buf, size, arg) };
    }
    // SAFETY: `format` is non-null and valid through its NUL terminator under
    // the printf-family C contract checked by `exact_direct_p_format`.
    if runtime_policy::strict_passthrough_active() && unsafe { exact_direct_p_format(format) } {
        // SAFETY: exact `%p` consumes one promoted `void *` variadic argument.
        let arg = unsafe { args.next_arg::<*mut c_void>() };
        // SAFETY: snprintf's C contract supplies `size` writable bytes when
        // `size > 0`; the helper bounds every write to that region.
        return unsafe { strict_direct_snprintf_p(str_buf, size, arg) };
    }

    let _trace_scope = runtime_policy::entrypoint_scope("snprintf");

    let (mode, decision) = runtime_policy::decide(
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

    if let Some(append_newline) = unsafe { exact_direct_s_format(format) } {
        let arg = unsafe { args.next_arg::<*const c_char>() };
        return unsafe { direct_snprintf_s(str_buf, size, arg, append_newline, mode, decision) };
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };

    // Fast path for ubiquitous exact "%s" and "%s\n": copy the string
    // argument straight to the destination, skipping the render engine and
    // intermediate buffer copy. NULL falls through so render emits "(null)".
    let _rendered_hold;
    let (src_ptr, src_len, append_newline, total_len) = if !fmt_bytes.contains(&b'%') {
        // Pure-literal format: output is the format verbatim — skip parse/extract/render
        // entirely; the truncating copy-out below handles `size`/NUL byte-identically.
        (fmt_bytes.as_ptr(), fmt_bytes.len(), false, fmt_bytes.len())
    } else {
        let segments = parse_format_string(fmt_bytes);
        let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
        let mut arg_buf = [0u64; MAX_VA_ARGS];
        extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);
        match unsafe { direct_printf_string_payload(fmt_bytes, arg_buf.as_ptr(), extract_count) } {
            Some(DirectPrintfPayload::String(bytes)) => {
                (bytes.as_ptr(), bytes.len(), false, bytes.len())
            }
            Some(DirectPrintfPayload::StringNewline(bytes)) => (
                bytes.as_ptr(),
                bytes.len(),
                true,
                bytes.len().saturating_add(1),
            ),
            None => {
                // Reuse the segments parsed above instead of re-parsing in render_printf.
                let rendered =
                    unsafe { render_segments(&segments, arg_buf.as_ptr(), extract_count, false) };
                let parts = (rendered.as_ptr(), rendered.len(), false, rendered.len());
                _rendered_hold = rendered;
                parts
            }
        }
    };

    let mut copy_len = if size > 0 { total_len.min(size - 1) } else { 0 };
    let mut adverse = false;
    let mut has_room = size > 0 && !str_buf.is_null();

    if repair_enabled(mode.heals_enabled(), decision.action)
        && let Some(bound) = known_remaining(str_buf as usize)
    {
        let safe_size = size.min(bound);
        if safe_size == 0 {
            has_room = false;
            if size > 0 {
                adverse = true;
                global_healing_policy().record(&HealingAction::ClampSize {
                    requested: size,
                    clamped: 0,
                });
            }
        } else {
            let max_payload = safe_size.saturating_sub(1);
            if copy_len > max_payload {
                copy_len = max_payload;
                adverse = true;
                global_healing_policy().record(&HealingAction::TruncateWithNull {
                    requested: total_len.min(size.saturating_sub(1)).saturating_add(1),
                    truncated: copy_len,
                });
            }
        }
    }

    if has_room {
        unsafe {
            let src = std::slice::from_raw_parts(src_ptr, src_len);
            copy_direct_printf_payload(str_buf, src, append_newline, copy_len);
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
    if runtime_policy::strict_passthrough_active()
        && let Some(literal_len) = unsafe { strict_literal_format_len(format) }
    {
        return unsafe { strict_direct_sprintf_literal(str_buf, format, literal_len) };
    }
    if runtime_policy::strict_passthrough_active() && unsafe { exact_direct_c_format(format) } {
        let arg = unsafe { args.next_arg::<c_int>() };
        return unsafe { strict_direct_sprintf_c(str_buf, arg) };
    }

    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Stdio, str_buf as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let fmt_bytes = unsafe { c_str_bytes(format) };

    // Fast path for exact "%s" and "%s\n" (see snprintf): copy the string
    // argument straight to the destination, skipping the render engine and its
    // intermediate buffer copy. NULL falls through so render emits "(null)".
    let _rendered_hold;
    let (src_ptr, src_len, append_newline, total_len) = if !fmt_bytes.contains(&b'%') {
        // Pure-literal format: output is the format verbatim — skip parse/extract/render.
        (fmt_bytes.as_ptr(), fmt_bytes.len(), false, fmt_bytes.len())
    } else {
        let segments = parse_format_string(fmt_bytes);
        let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
        let mut arg_buf = [0u64; MAX_VA_ARGS];
        extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);
        match unsafe { direct_printf_string_payload(fmt_bytes, arg_buf.as_ptr(), extract_count) } {
            Some(DirectPrintfPayload::String(bytes)) => {
                (bytes.as_ptr(), bytes.len(), false, bytes.len())
            }
            Some(DirectPrintfPayload::StringNewline(bytes)) => (
                bytes.as_ptr(),
                bytes.len(),
                true,
                bytes.len().saturating_add(1),
            ),
            None => {
                let rendered =
                    unsafe { render_segments(&segments, arg_buf.as_ptr(), extract_count, false) };
                let parts = (rendered.as_ptr(), rendered.len(), false, rendered.len());
                _rendered_hold = rendered;
                parts
            }
        }
    };

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
            let src = std::slice::from_raw_parts(src_ptr, src_len);
            copy_direct_printf_payload(str_buf, src, append_newline, copy_len);
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
    // Pure-literal fast path: no '%' ⇒ output is the format verbatim; skip the whole
    // parse/count/extract/render pipeline. Cached Full-buffered stream → inline write;
    // any miss (not cached / not Full / has '%') falls through to the normal path.
    if !fmt_bytes.contains(&b'%') && try_fwrite_fast(id, fmt_bytes) {
        return printf_result_to_c_int(fmt_bytes.len());
    }
    let segments = parse_format_string(fmt_bytes);
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let direct_payload =
        unsafe { direct_printf_string_payload(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    if let Some(DirectPrintfPayload::StringNewline(bytes)) = direct_payload {
        let total_len = bytes.len().saturating_add(1);
        if let Some(success) = unsafe { try_write_direct_s_newline_stream(id, bytes) } {
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                !success,
            );
            return if success {
                printf_result_to_c_int(total_len)
            } else {
                -1
            };
        }
    }

    // Bare "%s" fast path: emit the string straight to the stream, else render.
    let mut _bare_hold = None;
    let bytes = match direct_payload {
        Some(DirectPrintfPayload::String(bytes)) => bytes,
        _ => unsafe {
            bare_s_or_render(
                fmt_bytes,
                &segments,
                arg_buf.as_ptr(),
                extract_count,
                &mut _bare_hold,
            )
        },
    };
    let total_len = bytes.len();

    // Single-threaded inline fast path: append the rendered bytes to the cached
    // Full-buffered fd stream if they all fit (skip the registry lock + lookup). Common for
    // small fprintf/printf to a redirected (Full-buffered) stream. Miss → full path.
    if try_fwrite_fast(id, bytes) {
        return printf_result_to_c_int(total_len);
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        if s.is_mem_backed() {
            let written = s.mem_write(bytes);
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

        // Cache the resolved fd stream so subsequent single-threaded printf/write calls
        // hit the inline fast path (try_fwrite_fast).
        write_cache_store(id, s as *mut StdioStream);
        let write_result = match s.buffer_write(bytes) {
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
        // Host delegation path - not available in standalone mode
        #[cfg(not(feature = "standalone"))]
        if let Some(host_fwrite) = unsafe { host_fwrite_fn() } {
            let written = unsafe { host_fwrite(bytes.as_ptr().cast(), 1, bytes.len(), stream) };
            if written > 0 {
                mark_host_io_started(stream);
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                written < bytes.len(),
            );
            return if written == bytes.len() {
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
    // Pure-literal fast path: no '%' ⇒ output is the format verbatim; skip the whole
    // parse/count/extract/render pipeline. Cached Full-buffered stream → inline write;
    // any miss (not cached / not Full / has '%') falls through to the normal path.
    if !fmt_bytes.contains(&b'%') && try_fwrite_fast(id, fmt_bytes) {
        return printf_result_to_c_int(fmt_bytes.len());
    }
    let segments = parse_format_string(fmt_bytes);
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    extract_va_args!(&segments, &mut args, &mut arg_buf, extract_count);

    let direct_payload =
        unsafe { direct_printf_string_payload(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    if let Some(DirectPrintfPayload::StringNewline(bytes)) = direct_payload {
        let total_len = bytes.len().saturating_add(1);
        if let Some(success) = unsafe { try_write_direct_s_newline_stream(id, bytes) } {
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                !success,
            );
            return if success {
                printf_result_to_c_int(total_len)
            } else {
                -1
            };
        }
    }

    // Bare "%s" fast path: emit the string straight to the stream, else render.
    let mut _bare_hold = None;
    let bytes = match direct_payload {
        Some(DirectPrintfPayload::String(bytes)) => bytes,
        _ => unsafe {
            bare_s_or_render(
                fmt_bytes,
                &segments,
                arg_buf.as_ptr(),
                extract_count,
                &mut _bare_hold,
            )
        },
    };
    let total_len = bytes.len();

    // Single-threaded inline fast path: append the rendered bytes to the cached
    // Full-buffered fd stream if they all fit (skip the registry lock + lookup). Common for
    // small fprintf/printf to a redirected (Full-buffered) stream. Miss → full path.
    if try_fwrite_fast(id, bytes) {
        return printf_result_to_c_int(total_len);
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        if s.is_mem_backed() {
            let written = s.mem_write(bytes);
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

        // Cache the resolved fd stream so subsequent single-threaded printf/write calls
        // hit the inline fast path (try_fwrite_fast).
        write_cache_store(id, s as *mut StdioStream);
        let write_result = match s.buffer_write(bytes) {
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
        // Host delegation path - not available in standalone mode
        #[cfg(not(feature = "standalone"))]
        if let Some(host_fwrite) = unsafe { host_fwrite_fn() } {
            let written = unsafe { host_fwrite(bytes.as_ptr().cast(), 1, bytes.len(), stdout_ptr) };
            if written > 0 {
                mark_host_io_started(stdout_ptr);
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                written < bytes.len(),
            );
            return if written == bytes.len() {
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

    // Bare "%s" fast path: write the string straight to the fd, else render.
    let mut _bare_hold = None;
    let bytes = unsafe {
        bare_s_or_render(
            fmt_bytes,
            &segments,
            arg_buf.as_ptr(),
            extract_count,
            &mut _bare_hold,
        )
    };
    let total_len = bytes.len();

    let adverse = !write_all_fd(fd, bytes);
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

    // Bare "%s" fast path: use the string directly, else render.
    let mut _bare_hold = None;
    let bytes = unsafe {
        bare_s_or_render(
            fmt_bytes,
            &segments,
            arg_buf.as_ptr(),
            extract_count,
            &mut _bare_hold,
        )
    };
    let total_len = bytes.len();
    let alloc_size = total_len.saturating_add(1);

    // SAFETY: allocation size is computed from rendered payload and includes trailing NUL byte.
    let out = unsafe { malloc(alloc_size).cast::<c_char>() };
    if out.is_null() {
        unsafe { set_abi_errno(errno::ENOMEM) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast::<u8>(), total_len);
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
    // Reuse the segments parsed above instead of re-parsing in render_printf.
    let rendered = unsafe { render_segments(&segments, arg_buf.as_ptr(), extract, false) };
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
    if runtime_policy::strict_passthrough_active()
        && let Some(literal_len) = unsafe { strict_literal_format_len(format) }
    {
        return unsafe { strict_direct_snprintf_literal(str_buf, size, format, literal_len) };
    }
    let _trace_scope = runtime_policy::entrypoint_scope("vsnprintf");
    let (mode, decision) =
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

    // Fast path for ubiquitous exact "%s" and "%s\n": copy the string
    // argument straight to the destination, skipping the render engine and
    // intermediate buffer copy. NULL falls through so render emits "(null)".
    let _rendered_hold;
    let (src_ptr, src_len, append_newline, total_len) =
        match unsafe { direct_printf_string_payload(fmt_bytes, arg_buf.as_ptr(), extract_count) } {
            Some(DirectPrintfPayload::String(bytes)) => {
                (bytes.as_ptr(), bytes.len(), false, bytes.len())
            }
            Some(DirectPrintfPayload::StringNewline(bytes)) => (
                bytes.as_ptr(),
                bytes.len(),
                true,
                bytes.len().saturating_add(1),
            ),
            None => {
                // Reuse the segments parsed above instead of re-parsing in render_printf.
                let rendered =
                    unsafe { render_segments(&segments, arg_buf.as_ptr(), extract_count, false) };
                let parts = (rendered.as_ptr(), rendered.len(), false, rendered.len());
                _rendered_hold = rendered;
                parts
            }
        };

    let mut copy_len = if size > 0 { total_len.min(size - 1) } else { 0 };
    let mut adverse = false;
    let mut has_room = size > 0 && !str_buf.is_null();

    if repair_enabled(mode.heals_enabled(), decision.action)
        && let Some(bound) = known_remaining(str_buf as usize)
    {
        let safe_size = size.min(bound);
        if safe_size == 0 {
            has_room = false;
            if size > 0 {
                adverse = true;
                global_healing_policy().record(&HealingAction::ClampSize {
                    requested: size,
                    clamped: 0,
                });
            }
        } else {
            let max_payload = safe_size.saturating_sub(1);
            if copy_len > max_payload {
                copy_len = max_payload;
                adverse = true;
                global_healing_policy().record(&HealingAction::TruncateWithNull {
                    requested: total_len.min(size.saturating_sub(1)).saturating_add(1),
                    truncated: copy_len,
                });
            }
        }
    }

    if has_room {
        unsafe {
            let src = std::slice::from_raw_parts(src_ptr, src_len);
            copy_direct_printf_payload(str_buf, src, append_newline, copy_len);
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

    // Fast path for exact "%s" and "%s\n" (see snprintf): copy the string
    // argument straight to the destination, skipping the render engine and its
    // intermediate buffer copy. NULL falls through so render emits "(null)".
    let _rendered_hold;
    let (src_ptr, src_len, append_newline, total_len) =
        match unsafe { direct_printf_string_payload(fmt_bytes, arg_buf.as_ptr(), extract_count) } {
            Some(DirectPrintfPayload::String(bytes)) => {
                (bytes.as_ptr(), bytes.len(), false, bytes.len())
            }
            Some(DirectPrintfPayload::StringNewline(bytes)) => (
                bytes.as_ptr(),
                bytes.len(),
                true,
                bytes.len().saturating_add(1),
            ),
            None => {
                let rendered =
                    unsafe { render_segments(&segments, arg_buf.as_ptr(), extract_count, false) };
                let parts = (rendered.as_ptr(), rendered.len(), false, rendered.len());
                _rendered_hold = rendered;
                parts
            }
        };

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
            let src = std::slice::from_raw_parts(src_ptr, src_len);
            copy_direct_printf_payload(str_buf, src, append_newline, copy_len);
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
    // Pure-literal fast path: no '%' ⇒ output is the format verbatim; skip the whole
    // parse/count/extract/render pipeline. Cached Full-buffered stream → inline write;
    // any miss (not cached / not Full / has '%') falls through to the normal path.
    if !fmt_bytes.contains(&b'%') && try_fwrite_fast(id, fmt_bytes) {
        return printf_result_to_c_int(fmt_bytes.len());
    }
    let segments = parse_format_string(fmt_bytes);
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    unsafe { vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let direct_payload =
        unsafe { direct_printf_string_payload(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    if let Some(DirectPrintfPayload::StringNewline(bytes)) = direct_payload {
        let total_len = bytes.len().saturating_add(1);
        if let Some(success) = unsafe { try_write_direct_s_newline_stream(id, bytes) } {
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                !success,
            );
            return if success {
                printf_result_to_c_int(total_len)
            } else {
                -1
            };
        }
    }

    // Bare "%s" fast path: emit the string straight to the stream, else render.
    let mut _bare_hold = None;
    let bytes = match direct_payload {
        Some(DirectPrintfPayload::String(bytes)) => bytes,
        _ => unsafe {
            bare_s_or_render(
                fmt_bytes,
                &segments,
                arg_buf.as_ptr(),
                extract_count,
                &mut _bare_hold,
            )
        },
    };
    let total_len = bytes.len();

    // Single-threaded inline fast path: append the rendered bytes to the cached
    // Full-buffered fd stream if they all fit (skip the registry lock + lookup). Common for
    // small fprintf/printf to a redirected (Full-buffered) stream. Miss → full path.
    if try_fwrite_fast(id, bytes) {
        return printf_result_to_c_int(total_len);
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        if s.is_mem_backed() {
            let written = s.mem_write(bytes);
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

        // Cache the resolved fd stream so subsequent single-threaded printf/write calls
        // hit the inline fast path (try_fwrite_fast).
        write_cache_store(id, s as *mut StdioStream);
        let write_result = match s.buffer_write(bytes) {
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
        // Host delegation path - not available in standalone mode
        #[cfg(not(feature = "standalone"))]
        if let Some(host_fwrite) = unsafe { host_fwrite_fn() } {
            let written = unsafe { host_fwrite(bytes.as_ptr().cast(), 1, bytes.len(), stream) };
            if written > 0 {
                mark_host_io_started(stream);
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                written < bytes.len(),
            );
            return if written == bytes.len() {
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
    // Pure-literal fast path: no '%' ⇒ output is the format verbatim; skip the whole
    // parse/count/extract/render pipeline. Cached Full-buffered stream → inline write;
    // any miss (not cached / not Full / has '%') falls through to the normal path.
    if !fmt_bytes.contains(&b'%') && try_fwrite_fast(id, fmt_bytes) {
        return printf_result_to_c_int(fmt_bytes.len());
    }
    let segments = parse_format_string(fmt_bytes);
    let extract_count = core_count_printf_args(&segments).min(MAX_VA_ARGS);
    let mut arg_buf = [0u64; MAX_VA_ARGS];
    unsafe { vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };

    let direct_payload =
        unsafe { direct_printf_string_payload(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    if let Some(DirectPrintfPayload::StringNewline(bytes)) = direct_payload {
        let total_len = bytes.len().saturating_add(1);
        if let Some(success) = unsafe { try_write_direct_s_newline_stream(id, bytes) } {
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                !success,
            );
            return if success {
                printf_result_to_c_int(total_len)
            } else {
                -1
            };
        }
    }

    // Bare "%s" fast path: emit the string straight to the stream, else render.
    let mut _bare_hold = None;
    let bytes = match direct_payload {
        Some(DirectPrintfPayload::String(bytes)) => bytes,
        _ => unsafe {
            bare_s_or_render(
                fmt_bytes,
                &segments,
                arg_buf.as_ptr(),
                extract_count,
                &mut _bare_hold,
            )
        },
    };
    let total_len = bytes.len();

    // Single-threaded inline fast path: append the rendered bytes to the cached
    // Full-buffered fd stream if they all fit (skip the registry lock + lookup). Common for
    // small fprintf/printf to a redirected (Full-buffered) stream. Miss → full path.
    if try_fwrite_fast(id, bytes) {
        return printf_result_to_c_int(total_len);
    }

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        if s.is_mem_backed() {
            let written = s.mem_write(bytes);
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

        // Cache the resolved fd stream so subsequent single-threaded printf/write calls
        // hit the inline fast path (try_fwrite_fast).
        write_cache_store(id, s as *mut StdioStream);
        let write_result = match s.buffer_write(bytes) {
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
        // Host delegation path - not available in standalone mode
        #[cfg(not(feature = "standalone"))]
        if let Some(host_fwrite) = unsafe { host_fwrite_fn() } {
            let written = unsafe { host_fwrite(bytes.as_ptr().cast(), 1, bytes.len(), stdout_ptr) };
            if written > 0 {
                mark_host_io_started(stdout_ptr);
            }
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(15, total_len),
                written < bytes.len(),
            );
            return if written == bytes.len() {
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

    // Bare "%s" fast path: use the string directly, else render.
    let mut _bare_hold = None;
    let bytes = unsafe {
        bare_s_or_render(
            fmt_bytes,
            &segments,
            arg_buf.as_ptr(),
            extract_count,
            &mut _bare_hold,
        )
    };
    let total_len = bytes.len();

    let mut written = 0usize;
    let mut adverse = false;
    while written < total_len {
        let rc = unsafe { sys_write_fd(fd, bytes[written..].as_ptr().cast(), total_len - written) };
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

    // Bare "%s" fast path: use the string directly, else render.
    let mut _bare_hold = None;
    let bytes = unsafe {
        bare_s_or_render(
            fmt_bytes,
            &segments,
            arg_buf.as_ptr(),
            extract_count,
            &mut _bare_hold,
        )
    };
    let total_len = bytes.len();
    let alloc_size = total_len.saturating_add(1);

    let out = unsafe { malloc(alloc_size).cast::<c_char>() };
    if out.is_null() {
        unsafe { set_abi_errno(errno::ENOMEM) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast::<u8>(), total_len);
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

fn x86_extended80_bytes_from_f64(value: f64) -> [u8; 16] {
    let bits = value.to_bits();
    let sign = ((bits >> 63) as u16) << 15;
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1u64 << 52) - 1);

    let (significand, exponent_bits) = if exponent == 0 {
        if fraction == 0 {
            (0u64, sign)
        } else {
            let mut normalized = fraction;
            let mut unbiased = -1022i32;
            while normalized & (1u64 << 52) == 0 {
                normalized <<= 1;
                unbiased -= 1;
            }
            normalized &= (1u64 << 52) - 1;
            (
                (1u64 << 63) | (normalized << 11),
                sign | u16::try_from(unbiased + 16383).unwrap_or(0),
            )
        }
    } else if exponent == 0x7ff {
        let significand = if fraction == 0 {
            1u64 << 63
        } else {
            (1u64 << 63) | (fraction << 11)
        };
        (significand, sign | 0x7fff)
    } else {
        (
            (1u64 << 63) | (fraction << 11),
            sign | u16::try_from(exponent - 1023 + 16383).unwrap_or(0),
        )
    };

    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&significand.to_le_bytes());
    bytes[8..10].copy_from_slice(&exponent_bits.to_le_bytes());
    bytes
}

unsafe fn write_long_double_from_f64(dest: *mut c_void, value: f64) {
    let bytes = x86_extended80_bytes_from_f64(value);
    // SAFETY: `%Lf` callers provide a writable long-double destination. On the
    // supported Linux ABI used by this harness, the storage slot is 16 bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dest.cast::<u8>(), bytes.len());
    }
}

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
                    let ptr = $args.next_arg::<*mut i8>();
                    *ptr = *v as i8;
                }
                LengthMod::H => {
                    let ptr = $args.next_arg::<*mut i16>();
                    *ptr = *v as i16;
                }
                LengthMod::L | LengthMod::Ll | LengthMod::J => {
                    let ptr = $args.next_arg::<*mut i64>();
                    *ptr = *v;
                }
                LengthMod::Z | LengthMod::T => {
                    let ptr = $args.next_arg::<*mut isize>();
                    *ptr = *v as isize;
                }
                _ => {
                    let ptr = $args.next_arg::<*mut c_int>();
                    *ptr = *v as c_int;
                }
            },
            ScanValue::UnsignedInt(v) => match $spec.length {
                LengthMod::Hh => {
                    let ptr = $args.next_arg::<*mut u8>();
                    *ptr = *v as u8;
                }
                LengthMod::H => {
                    let ptr = $args.next_arg::<*mut u16>();
                    *ptr = *v as u16;
                }
                LengthMod::L | LengthMod::Ll | LengthMod::J => {
                    let ptr = $args.next_arg::<*mut u64>();
                    *ptr = *v;
                }
                LengthMod::Z | LengthMod::T => {
                    let ptr = $args.next_arg::<*mut usize>();
                    *ptr = *v as usize;
                }
                _ => {
                    let ptr = $args.next_arg::<*mut u32>();
                    *ptr = *v as u32;
                }
            },
            ScanValue::Float(v) => match $spec.length {
                LengthMod::BigL => {
                    let ptr = $args.next_arg::<*mut c_void>();
                    write_long_double_from_f64(ptr, *v);
                }
                LengthMod::L => {
                    let ptr = $args.next_arg::<*mut f64>();
                    *ptr = *v;
                }
                _ => {
                    let ptr = $args.next_arg::<*mut f32>();
                    // Preserve a NaN payload across the f64->f32 narrowing.
                    *ptr = frankenlibc_core::stdlib::conversion::narrow_f64_to_f32(*v);
                }
            },
            ScanValue::Char(bytes) => {
                if $spec.alloc {
                    // GNU `%mc`: allocate exactly `bytes.len()` bytes (no NUL,
                    // like glibc) and store the pointer in the caller's char**.
                    let pp = $args.next_arg::<*mut *mut c_char>();
                    let n = bytes.len().max(1);
                    let buf = malloc(n).cast::<u8>();
                    if !buf.is_null() {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
                    }
                    *pp = buf.cast::<c_char>();
                } else {
                    let ptr = $args.next_arg::<*mut u8>();
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
                }
            }
            ScanValue::String(bytes) => {
                if $spec.alloc {
                    // GNU `%ms` / `%m[`: allocate matched length + NUL and store
                    // the pointer in the caller's char**.
                    let pp = $args.next_arg::<*mut *mut c_char>();
                    let buf = malloc(bytes.len() + 1).cast::<u8>();
                    if !buf.is_null() {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
                        *buf.add(bytes.len()) = 0;
                    }
                    *pp = buf.cast::<c_char>();
                } else {
                    let ptr = $args.next_arg::<*mut c_char>();
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
                    *ptr.add(bytes.len()) = 0; // NUL-terminate
                }
            }
            ScanValue::CharsConsumed(n) => match $spec.length {
                LengthMod::Hh => {
                    let ptr = $args.next_arg::<*mut i8>();
                    *ptr = *n as i8;
                }
                LengthMod::H => {
                    let ptr = $args.next_arg::<*mut i16>();
                    *ptr = *n as i16;
                }
                LengthMod::L | LengthMod::Ll | LengthMod::J => {
                    let ptr = $args.next_arg::<*mut i64>();
                    *ptr = *n as i64;
                }
                _ => {
                    let ptr = $args.next_arg::<*mut c_int>();
                    *ptr = *n as c_int;
                }
            },
            ScanValue::Pointer(v) => {
                let ptr = $args.next_arg::<*mut *mut c_void>();
                *ptr = *v as *mut c_void;
            }
        }
    };
}

/// Core scanf logic: parse format, scan input, return result and directives.
pub(crate) fn scanf_core(
    input: &[u8],
    format: *const c_char,
) -> Option<(ScanResult, Vec<ScanDirective>)> {
    scanf_core_impl(input, format, false)
}

/// WIDE-stream variant for the `swscanf`/`fwscanf` family: `input` is the wide
/// input re-encoded as UTF-8, and narrow `%s`/`%c`/`%[` field widths count WIDE
/// characters (not bytes), matching the C wide-scanf semantics.
pub(crate) fn scanf_core_wide(
    input: &[u8],
    format: *const c_char,
) -> Option<(ScanResult, Vec<ScanDirective>)> {
    scanf_core_impl(input, format, true)
}

fn scanf_core_impl(
    input: &[u8],
    format: *const c_char,
    wide_input: bool,
) -> Option<(ScanResult, Vec<ScanDirective>)> {
    // PERF (bd-2g7oyh, same lever family as the sscanf input scan):
    // this is the SHARED scanf engine, so EVERY scanf variant (sscanf/fscanf/
    // vfscanf/vsscanf/wide) lengths a short caller FORMAT string here. Strict mode
    // takes the page-safe SWAR scan; hardened keeps the allocation-bound early-out.
    let (fmt_len, fmt_terminated) = unsafe { strict_c_str_len(format) };
    if !fmt_terminated {
        return None;
    }
    let fmt_bytes = unsafe { std::slice::from_raw_parts(format.cast::<u8>(), fmt_len) };
    let mut directives = parse_scanf_format(fmt_bytes);
    let result = if wide_input {
        // Mark every conversion as reading from a wide stream so leading-
        // whitespace skipping and `%s` token boundaries are Unicode-aware.
        for dir in &mut directives {
            if let ScanDirective::Spec(spec) = dir {
                spec.wide_input = true;
            }
        }
        frankenlibc_core::stdio::scanf::scan_input_wide(input, &directives)
    } else {
        scan_input(input, &directives)
    };
    Some((result, directives))
}

/// Origin metadata for a bulk scanf read.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ScanfReadState {
    /// Memory-backed stream; unread suffix is restored by rewinding backing.
    Memory,
    /// Seekable fd; unread suffix remains in the kernel after an `lseek`.
    SeekableFd { base: i64 },
    /// Non-seekable fd; unread suffix must be staged back into the stream.
    BufferedFd { base: i64 },
}

/// Read stream content into a byte buffer for scanf parsing.
///
/// Returns the bytes plus read-state metadata. Seekable fds are read from their
/// true logical offset so finalization can `lseek` to the parsed prefix. Memory
/// streams and non-seekable fds over-read into memory and finalize by restoring
/// the unread suffix to the backing or stream read queue.
pub(crate) fn read_stream_for_scanf(id: usize, limit: usize) -> (Vec<u8>, ScanfReadState) {
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        return (Vec::new(), ScanfReadState::Memory);
    };

    // Memory-backed streams: read directly (rewind handled by scanf_rewind_mem).
    if s.is_mem_backed() {
        sync_and_unregister_fast_fixed_mem_read(id, s);
        return (s.mem_read(limit), ScanfReadState::Memory);
    }

    let fd = s.fd();
    let cap = limit.min(8192);

    // Seekable read streams (regular files): read from the true logical
    // position so the post-parse lseek can leave the unparsed tail in place.
    // Gated on no pending writes — otherwise prepare_seek would discard them
    // (write-mixed streams keep the legacy raw-read path, see bd-2g7oyh.180).
    if s.pending_flush().is_empty() && raw_syscall::sys_lseek(fd, 0, libc::SEEK_CUR).is_ok() {
        let base = s.offset();
        // Discard any read-ahead buffer + ungetc and align the fd to `base`.
        let _ = s.prepare_seek();
        if raw_syscall::sys_lseek(fd, base, libc::SEEK_SET).is_ok() {
            let mut buf = vec![0u8; cap];
            let rc = unsafe { sys_read_fd(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if rc > 0 {
                buf.truncate(rc as usize);
                return (buf, ScanfReadState::SeekableFd { base });
            }
            if rc == 0 {
                s.set_eof();
            }
            return (Vec::new(), ScanfReadState::SeekableFd { base });
        }
        // lseek-back failed unexpectedly; fall through to the raw-read path.
    }

    // Non-seekable (pipe/socket) or write-mixed: read in logical stream order.
    // Drain existing buffered/ungetc bytes first, then bulk-read the fd. The
    // finalizer stages any unread suffix back into the stream read queue.
    let base = s.offset();
    let mut buf = s.buffered_read(cap);
    if buf.len() >= cap || s.is_eof() || s.is_error() {
        return (buf, ScanfReadState::BufferedFd { base });
    }

    let mut tmp = vec![0u8; cap - buf.len()];
    let rc = unsafe { sys_read_fd(fd, tmp.as_mut_ptr().cast(), tmp.len()) };
    if rc > 0 {
        tmp.truncate(rc as usize);
        buf.extend_from_slice(&tmp);
        (buf, ScanfReadState::BufferedFd { base })
    } else {
        if rc == 0 {
            s.set_eof();
        }
        (buf, ScanfReadState::BufferedFd { base })
    }
}

/// Finalize a scanf read: leave the unparsed remainder available to the next
/// read on the same stream (glibc consumes exactly the parsed prefix).
///
/// Seekable fds use `lseek(base + consumed)`. Memory-backed streams rewind the
/// backing by the unconsumed count. Non-seekable fds stage the unread suffix in
/// the stream so the next `fgetc`/`fread` observes it byte-for-byte.
pub(crate) fn scanf_finish_consume(
    id: usize,
    read_state: ScanfReadState,
    input: &[u8],
    consumed: usize,
) {
    let consumed = consumed.min(input.len());
    match read_state {
        ScanfReadState::SeekableFd { base } => {
            let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(s) = reg.streams.get_mut(&id) {
                let target = base.saturating_add(consumed as i64);
                let fd = s.fd();
                if raw_syscall::sys_lseek(fd, target, libc::SEEK_SET).is_ok() {
                    s.set_offset(target);
                }
            }
        }
        ScanfReadState::Memory => {
            rewind_unconsumed_scanf_mem(id, input.len().saturating_sub(consumed));
        }
        ScanfReadState::BufferedFd { base } => {
            stage_unconsumed_scanf_fd(id, base, input, consumed);
        }
    }
}

/// Rewind a memory-backed bulk scanf read by the unparsed count.
fn rewind_unconsumed_scanf_mem(id: usize, unconsumed: usize) {
    if unconsumed == 0 {
        return;
    }
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        s.scanf_rewind_mem(unconsumed);
    }
}

/// Stage unread bytes from a non-seekable fd bulk scanf read.
fn stage_unconsumed_scanf_fd(id: usize, base: i64, input: &[u8], consumed: usize) {
    let consumed = consumed.min(input.len());
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = reg.streams.get_mut(&id) {
        s.pushback_read_bytes(&input[consumed..]);
        s.set_offset(base.saturating_add(consumed as i64));
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

    if runtime_policy::strict_passthrough_active() {
        if let Some(fields) = unsafe { strict_decimal_int_format_count(format) } {
            let fast = unsafe { strict_scan_decimal_ints(s, fields) };
            for idx in 0..(fast.count.max(0) as usize).min(fields) {
                let ptr = unsafe { args.next_arg::<*mut c_int>() };
                unsafe { *ptr = fast.values[idx] };
            }
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, fast.input_failure);
            return fast.count;
        }
    }

    // PERF (bd-2g7oyh):
    // sscanf/vsscanf parse a CALLER STRING (no stream / no registry lock), so this
    // is strlen+parse-dominated. Strict mode uses the page-safe SWAR scan; hardened
    // keeps the allocation-bound EOF branch for fl-tracked unterminated buffers.
    let (input_len, input_terminated) = unsafe { strict_c_str_len(s) };
    if !input_terminated {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }
    let input = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), input_len) };
    let Some((result, directives)) = scanf_core(input, format) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    };

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
    if stream.is_null() || format.is_null() {
        return -1;
    }
    let id = canonical_stream_id(stream);
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    let (input_buf, scanf_seek_base) = read_stream_for_scanf(id, 8192);
    if input_buf.is_empty() {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }

    let Some((result, directives)) = scanf_core(&input_buf, format) else {
        scanf_finish_consume(id, scanf_seek_base, &input_buf, 0);
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    };

    // Restore the bytes scanf did not parse (glibc consumes exactly the prefix).
    scanf_finish_consume(id, scanf_seek_base, &input_buf, result.consumed);

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

    let (input_buf, scanf_seek_base) = read_stream_for_scanf(STDIN_SENTINEL, 8192);
    if input_buf.is_empty() {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }

    let Some((result, directives)) = scanf_core(&input_buf, format) else {
        scanf_finish_consume(STDIN_SENTINEL, scanf_seek_base, &input_buf, 0);
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    };

    // Restore the bytes scanf did not parse (glibc consumes exactly the prefix).
    scanf_finish_consume(STDIN_SENTINEL, scanf_seek_base, &input_buf, result.consumed);

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

    // PERF (bd-2g7oyh):
    // sscanf/vsscanf parse a CALLER STRING (no stream / no registry lock), so this
    // is strlen+parse-dominated. Strict mode uses the page-safe SWAR scan; hardened
    // keeps the allocation-bound EOF branch for fl-tracked unterminated buffers.
    let (input_len, input_terminated) = unsafe { strict_c_str_len(s) };
    if !input_terminated {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }
    let input = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), input_len) };
    let Some((result, directives)) = scanf_core(input, format) else {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    };

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
    if stream.is_null() || format.is_null() || ap.is_null() {
        return -1;
    }
    let id = canonical_stream_id(stream);
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
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

    let (input_buf, scanf_seek_base) = read_stream_for_scanf(id, 8192);
    if input_buf.is_empty() {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    }

    let Some((result, directives)) = scanf_core(&input_buf, format) else {
        scanf_finish_consume(id, scanf_seek_base, &input_buf, 0);
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return libc::EOF;
    };

    // Restore the bytes scanf did not parse (glibc consumes exactly the prefix).
    scanf_finish_consume(id, scanf_seek_base, &input_buf, result.consumed);

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
            LengthMod::BigL => unsafe { write_long_double_from_f64(dest, *v) },
            LengthMod::L => unsafe { *(dest as *mut f64) = *v },
            _ => unsafe {
                // Preserve a NaN payload across the f64->f32 narrowing.
                *(dest as *mut f32) = frankenlibc_core::stdlib::conversion::narrow_f64_to_f32(*v)
            },
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

    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
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

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = reg.streams.get_mut(&id) else {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return -1;
    };
    let _ = sync_fast_fixed_mem_read_to_stream(id, s);

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

    let _id = canonical_stream_id(stream);
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
    if !registry_contains_stream(_id)
        && let Some(host_fsetpos) = unsafe { host_fsetpos_fn() }
    {
        let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, _id, 0, false, false, 0);
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
    let (mode_len, mode_terminated) = unsafe { scan_c_str_len(mode, None) };
    if !mode_terminated {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return std::ptr::null_mut();
    }
    let mode_bytes = unsafe { std::slice::from_raw_parts(mode.cast::<u8>(), mode_len) };
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

    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
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
    if let Some(mut old) = reg.remove_stream(id) {
        if old.is_mem_backed() {
            sync_and_unregister_fast_fixed_mem_read(id, &mut old);
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
    reg.insert_stream(id, new_stream);

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
thread_local! {
    /// Reusable getdelim scratch buffer — avoids a fresh `Vec::with_capacity(128)` (a per-line
    /// fl-malloc, ~61ns, that glibc doesn't pay) on every getdelim/getline call. Retains its
    /// capacity across calls; a drop guard restores it on every return path.
    static GETDELIM_SCRATCH: std::cell::Cell<Vec<u8>> = const { std::cell::Cell::new(Vec::new()) };
}

struct GetdelimScratchGuard(Vec<u8>);
impl Drop for GetdelimScratchGuard {
    fn drop(&mut self) {
        // Return the (grown) buffer to the thread-local so its capacity is reused next call.
        GETDELIM_SCRATCH.with(|c| c.set(std::mem::take(&mut self.0)));
    }
}

/// Shared getdelim read loop: fill `buf` from `s` through the first `delim_byte`, or EOF/
/// error. Bulk-scans the stream buffer via read_until_delim (no per-char re-lock), refilling
/// the fd. Extracted verbatim from the original loop so both the slow path (registry lock
/// held) and the ST pointer-keyed fast path (cache-gated) share one implementation.
///
/// # Safety
/// `s` must be uniquely borrowed for this call (registry lock held, or ST cache-gated).
unsafe fn getdelim_fill_stream(s: &mut StdioStream, delim_byte: u8, buf: &mut Vec<u8>) {
    loop {
        match s.read_until_delim(delim_byte, &mut *buf) {
            ReadUntil::Found | ReadUntil::Eof => break,
            ReadUntil::NeedRefill => {
                if s.is_eof() || s.is_error() {
                    break;
                }
                if s.buffer_capacity() == 0 {
                    // Unbuffered fd stream: read a byte directly.
                    let mut b = [0u8; 1];
                    let fd = s.fd();
                    let rc = unsafe { sys_read_fd(fd, b.as_mut_ptr().cast(), 1) };
                    if rc > 0 {
                        s.set_offset(s.offset().saturating_add(1));
                        buf.push(b[0]);
                        if b[0] == delim_byte {
                            break;
                        }
                    } else if rc == 0 {
                        s.set_eof();
                        break;
                    } else {
                        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                        if e != errno::EINTR {
                            s.set_error();
                        }
                        break;
                    }
                } else if unsafe { refill_stream(s) } <= 0 {
                    break;
                }
            }
        }
    }
}

/// Shared getdelim tail: (re)allocate `*lineptr` to fit `buf` + NUL, copy, NUL-terminate.
/// Returns the line length, or -1 (empty read / ENOMEM). No observe/membrane — the caller
/// handles telemetry (the fast path skips it).
///
/// # Safety
/// `lineptr`/`n` are valid getdelim out-params; `*lineptr` (if non-null) was
/// returned by a compatible allocator entrypoint.
unsafe fn getdelim_finish(buf: &[u8], lineptr: *mut *mut c_char, n: *mut usize) -> isize {
    if buf.is_empty() {
        return -1;
    }
    let needed = buf.len() + 1; // +1 for NUL terminator
    let current_buf = unsafe { *lineptr };
    let current_size = unsafe { *n };
    let out_buf = if current_buf.is_null() || current_size < needed {
        let new_size = needed.max(128);
        // SAFETY: FrankenLibC realloc routes segment, fallback-tracked host,
        // and unknown host pointers through their matching ownership path.
        let new_buf = unsafe { crate::malloc_abi::realloc(current_buf.cast(), new_size) };
        if new_buf.is_null() {
            unsafe { set_abi_errno(errno::ENOMEM) };
            return -1;
        }
        unsafe { *lineptr = new_buf.cast() };
        unsafe { *n = new_size };
        new_buf as *mut u8
    } else {
        current_buf as *mut u8
    };
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), out_buf, buf.len());
        *out_buf.add(buf.len()) = 0; // NUL terminate
    }
    buf.len() as isize
}

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

    let delim_byte = delim as u8;

    // ST fast path: a cache hit is a non-cookie non-mem fd stream, so fill lock-free + finish,
    // skipping canonical_stream_id's native lock + registry_contains + registry().lock() +
    // decide/observe per line (getline is hot for file processing). Byte-identical.
    if let Some(p) = write_cache_lookup_by_stream(stream) {
        let mut scratch = GetdelimScratchGuard(GETDELIM_SCRATCH.with(|c| c.take()));
        let buf = &mut scratch.0;
        buf.clear();
        // SAFETY: ST-gated + gen-valid ⇒ unique &mut for this call.
        unsafe { getdelim_fill_stream(&mut *p, delim_byte, buf) };
        return unsafe { getdelim_finish(buf, lineptr, n) };
    }

    let id = canonical_stream_id(stream);
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
    if !registry_contains_stream(id)
        && let Some(host_getdelim) = unsafe { host_getdelim_fn() }
    {
        let Some(prepared) =
            (unsafe { crate::malloc_abi::prepare_host_realloc_buffer((*lineptr).cast(), *n) })
        else {
            unsafe { set_abi_errno(errno::ENOMEM) };
            return -1;
        };
        unsafe { *lineptr = prepared.cast() };
        let rc = unsafe { host_getdelim(lineptr, n, delim, stream) };
        crate::malloc_abi::finish_host_realloc_buffer(unsafe { (*lineptr).cast() }, unsafe { *n });
        if rc < 0 {
            unsafe { sync_host_errno(0) };
        } else {
            mark_host_io_started(stream);
        }
        return rc;
    }
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, id, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
        return -1;
    }

    // Reuse the thread-local scratch (retains capacity) instead of a fresh per-call Vec.
    let mut scratch = GetdelimScratchGuard(GETDELIM_SCRATCH.with(|c| c.take()));
    let buf = &mut scratch.0;
    buf.clear();

    // Read the whole line under a SINGLE registry lock + the policy decision above (bulk
    // read_until_delim, not per-char fgetc; the ABI layer owns descriptor refill).
    {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = reg.streams.get_mut(&id) else {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, true);
            return -1;
        };
        if s.is_mem_backed() {
            sync_and_unregister_fast_fixed_mem_read(id, s);
        } else if !is_cookie_stream(id) {
            // Cache the non-cookie non-mem fd stream so subsequent getdelim/getline hit the
            // fast path — a pure getline loop otherwise never populates the cache. See fgets.
            write_cache_store(id, s as *mut StdioStream);
        }
        // SAFETY: `s` uniquely borrowed under the registry lock.
        unsafe { getdelim_fill_stream(s, delim_byte, buf) };
    }

    let r = unsafe { getdelim_finish(buf, lineptr, n) };
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 15, r < 0);
    r
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

    let _id = canonical_stream_id(stream);
    // Host delegation path - not available in standalone mode
    #[cfg(not(feature = "standalone"))]
    if !registry_contains_stream(_id)
        && let Some(host_getline) = unsafe { host_getline_fn() }
    {
        let Some(prepared) =
            (unsafe { crate::malloc_abi::prepare_host_realloc_buffer((*lineptr).cast(), *n) })
        else {
            unsafe { set_abi_errno(errno::ENOMEM) };
            return -1;
        };
        unsafe { *lineptr = prepared.cast() };
        let rc = unsafe { host_getline(lineptr, n, stream) };
        crate::malloc_abi::finish_host_realloc_buffer(unsafe { (*lineptr).cast() }, unsafe { *n });
        if rc < 0 {
            unsafe { sync_host_errno(0) };
        } else {
            mark_host_io_started(stream);
        }
        return rc;
    }
    unsafe { getdelim(lineptr, n, b'\n' as c_int, stream) }
}

/// glibc reserved-namespace alias for [`getline`]. Some headers
/// and a few third-party callers link against the underscored
/// variant instead of the public name.
///
/// # Safety
///
/// Same as [`getline`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getline(
    lineptr: *mut *mut c_char,
    n: *mut usize,
    stream: *mut c_void,
) -> isize {
    unsafe { getline(lineptr, n, stream) }
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

#[cfg(feature = "owned-tls-cache")]
static TMPNAM_BUF_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<[u8; 64]> =
    crate::owned_tls_cache::OwnedTlsCache::new(|| [0; 64]);

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static TMPNAM_BUF: std::cell::UnsafeCell<[u8; 64]> = const { std::cell::UnsafeCell::new([0u8; 64]) };
}

fn tmpnam_static_buffer(name: &[u8], total: usize) -> *mut c_char {
    #[cfg(feature = "owned-tls-cache")]
    {
        TMPNAM_BUF_OWNED_TLS.with(|buf| {
            // SAFETY: `buf` is the per-thread static tmpnam buffer and `total`
            // is bounded by the fixed local formatter buffer.
            unsafe { std::ptr::copy_nonoverlapping(name.as_ptr(), buf.as_mut_ptr(), total) };
            buf.as_ptr() as *mut c_char
        })
    }

    #[cfg(not(feature = "owned-tls-cache"))]
    {
        TMPNAM_BUF.with(|cell| {
            let buf = cell.get();
            // SAFETY: `buf` is the per-thread static tmpnam buffer and `total`
            // is bounded by the fixed local formatter buffer.
            unsafe {
                std::ptr::copy_nonoverlapping(name.as_ptr(), (*buf).as_mut_ptr(), total);
                (*buf).as_ptr() as *mut c_char
            }
        })
    }
}

/// POSIX `tmpnam` — generate a unique temporary file name.
///
/// If `s` is not NULL, the name is written to the buffer pointed to by `s`
/// (which must be at least `L_tmpnam` bytes). If `s` is NULL, a static
/// buffer is used (NOT thread-safe in that case).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tmpnam(s: *mut c_char) -> *mut c_char {
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
        tmpnam_static_buffer(&name, total)
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
static POPEN_PIDS: Mutex<Option<ArtifactHashMap<usize, i32>>> = Mutex::new(None);

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

    let (mode_len, mode_terminated) = unsafe { scan_c_str_len(typ, None) };
    if !mode_terminated {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 50, true);
        return std::ptr::null_mut();
    }
    let mode_bytes = unsafe { std::slice::from_raw_parts(typ.cast::<u8>(), mode_len) };
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
        let map = guard.get_or_insert_with(artifact_hash_map);
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
static COOKIE_REGISTRY: Mutex<Option<ArtifactHashMap<usize, CookieStreamInfo>>> = Mutex::new(None);

/// Monotonic "has any cookie stream ever been created?" flag. `fopencookie` is
/// rare; the overwhelmingly common case is that NO cookie stream exists, yet
/// every `fgetc`/`fputs`/`fputc` calls [`is_cookie_stream`], which otherwise
/// takes the `COOKIE_REGISTRY` mutex just to learn "no". This lets the hot path
/// skip that lock entirely until the first `fopencookie`. It is never reset to
/// false (cookie streams are rare and the reset would race a concurrent
/// `fopencookie`), so once set the locked check resumes — still correct.
static COOKIE_STREAMS_PRESENT: AtomicBool = AtomicBool::new(false);

fn cookie_registry() -> &'static Mutex<Option<ArtifactHashMap<usize, CookieStreamInfo>>> {
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
    // Lock-free fast path: if no cookie stream has ever been registered, the id
    // cannot be cookie-backed. A new cookie id is only published (returned from
    // `fopencookie`) AFTER the `Release` store below, so any `is_cookie_stream`
    // for a real cookie id happens-after this `Acquire` load observes `true`.
    if !COOKIE_STREAMS_PRESENT.load(Ordering::Acquire) {
        return false;
    }
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
static MEM_STREAM_SYNC: Mutex<Option<ArtifactHashMap<usize, MemStreamSync>>> = Mutex::new(None);

/// Monotonic "has any `open_memstream` ever been created?" flag (cookie-pattern
/// twin of `COOKIE_STREAMS_PRESENT`). `sync_memstream_to_caller` runs on every
/// mem-backed flush/close but only does work for `open_memstream` ids; without
/// any such stream the lock + lookup is pure waste. Set on `open_memstream`
/// (Release), loaded with Acquire, never reset (the stream's sentinel id is only
/// published after the store, so the fast path is correct).
static MEM_STREAM_SYNC_PRESENT: AtomicBool = AtomicBool::new(false);

fn mem_sync_registry() -> &'static Mutex<Option<ArtifactHashMap<usize, MemStreamSync>>> {
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
static MEM_FIXED_SYNC: Mutex<Option<ArtifactHashMap<usize, MemFixedSync>>> = Mutex::new(None);

/// Monotonic "has any `fmemopen` fixed-buffer stream ever been created?" flag
/// (cookie-pattern twin of `MEM_STREAM_SYNC_PRESENT`). `sync_fmemopen_full` runs
/// on every mem-backed flush/close but only does work for fmemopen-fixed ids;
/// without any such stream the lock + lookup is pure waste. Set on `fmemopen`
/// (Release), loaded with Acquire, never reset (the stream's sentinel id is only
/// published after the store, so the fast path is correct).
static MEM_FIXED_SYNC_PRESENT: AtomicBool = AtomicBool::new(false);

fn mem_fixed_registry() -> &'static Mutex<Option<ArtifactHashMap<usize, MemFixedSync>>> {
    &MEM_FIXED_SYNC
}

/// Synchronize the full fmemopen fixed buffer contents to the caller.
unsafe fn sync_fmemopen_full(id: usize, stream: &StdioStream) {
    // Lock-free fast path: no fmemopen-fixed stream has ever been created, so this
    // id cannot have fixed-buffer metadata. The id is only published after the
    // Release store in `fmemopen`, so this Acquire load is correct.
    if !MEM_FIXED_SYNC_PRESENT.load(Ordering::Acquire) {
        return;
    }
    let guard = mem_fixed_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(ref map) = *guard
        && let Some(info) = map.get(&id)
        && let Some(data) = stream.mem_data()
    {
        let len = data.len().min(info.size);
        let copy_len = if stream.is_truncating() && len == info.size && info.size > 0 {
            info.size - 1
        } else {
            len
        };
        if copy_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), info.buf, copy_len);
            }
        }
        if copy_len < info.size && (copy_len > 0 || stream.is_readable()) {
            unsafe {
                *info.buf.add(copy_len) = 0;
            }
        }
    }
}

/// Synchronize open_memstream data to the C caller's pointers.
/// Called after fflush and fclose for open_memstream streams.
unsafe fn sync_memstream_to_caller(id: usize, stream: &StdioStream) {
    // Lock-free fast path: no open_memstream has ever been created, so this id
    // cannot have sync metadata. A new open_memstream id is only published after
    // the Release store in `open_memstream`, so this Acquire load is correct.
    if !MEM_STREAM_SYNC_PRESENT.load(Ordering::Acquire) {
        return;
    }
    let sync_guard = mem_sync_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(ref map) = *sync_guard
        && let Some(info) = map.get(&id)
        && let Some(data) = stream.mem_data()
    {
        let len = data.len();
        // POSIX: *sizeloc is the SMALLER of the buffer's content length and the
        // current file position — so seeking backwards and writing shrinks the
        // reported size even though the tail bytes (and the NUL terminator at the
        // max extent) survive in the buffer. fl previously reported the full
        // content length, diverging from glibc after a backward seek.
        let pos = stream.offset().max(0) as usize;
        let reported = len.min(pos);
        let previous = unsafe { *info.ptr_loc };
        // Allocate a new buffer via malloc and copy data + NUL terminator.
        let buf = unsafe { malloc(len + 1) };
        if !buf.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), buf.cast::<u8>(), len);
                *buf.cast::<u8>().add(len) = 0; // NUL-terminate at the max extent
                *info.ptr_loc = buf.cast::<c_char>();
                *info.size_loc = reported;
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
            // Host delegation path - not available in standalone mode
            #[cfg(not(feature = "standalone"))]
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
            // Host delegation path - not available in standalone mode
            #[cfg(not(feature = "standalone"))]
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
            // Host delegation path - not available in standalone mode
            #[cfg(not(feature = "standalone"))]
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
    // glibc accepts size 0 (since 2.22): a valid, empty stream whose reads hit
    // EOF immediately. The buffer handling below already produces an empty Vec
    // and zero content length for size 0, so only a null mode is rejected.
    if mode.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    // Parse mode string.
    let (mode_len, mode_terminated) = unsafe { scan_c_str_len(mode, None) };
    if !mode_terminated {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }
    let mode_bytes = unsafe { std::slice::from_raw_parts(mode.cast::<u8>(), mode_len) };
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

    let fast_read_data = if open_flags.readable && !open_flags.writable {
        Some(data[..content_len].to_vec())
    } else {
        None
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
    if let Some(fast_read_data) = fast_read_data {
        register_fast_fixed_mem_read(id, fast_read_data);
    }

    if !buf.is_null() {
        let mut guard = mem_fixed_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let map = guard.get_or_insert_with(artifact_hash_map);
        map.insert(
            id,
            MemFixedSync {
                buf: buf.cast::<u8>(),
                size,
            },
        );
        // Publish before releasing the lock and before the stream id is returned,
        // so the lock-free fast path in `sync_fmemopen_full` is correct.
        MEM_FIXED_SYNC_PRESENT.store(true, Ordering::Release);
        if open_flags.truncate && open_flags.readable && size > 0 {
            unsafe {
                *buf.cast::<u8>() = 0;
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
    let map = sync_guard.get_or_insert_with(artifact_hash_map);
    map.insert(
        id,
        MemStreamSync {
            ptr_loc: ptr,
            size_loc: sizeloc,
        },
    );
    // Publish before releasing the lock and before the stream id is returned, so
    // the lock-free fast path in `sync_memstream_to_caller` is correct.
    MEM_STREAM_SYNC_PRESENT.store(true, Ordering::Release);
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

    // Parse mode string.
    let (mode_len, mode_terminated) = unsafe { scan_c_str_len(mode, None) };
    if !mode_terminated {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }
    let mode_bytes = unsafe { std::slice::from_raw_parts(mode.cast::<u8>(), mode_len) };
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
    reg.insert_stream(id, stream);
    drop(reg);

    // Register the cookie info
    let mut cookie_guard = cookie_registry().lock().unwrap_or_else(|e| e.into_inner());
    let map = cookie_guard.get_or_insert_with(artifact_hash_map);
    map.insert(
        id,
        CookieStreamInfo {
            cookie,
            funcs: io_funcs,
        },
    );
    // Publish before releasing the lock and before the id is returned, so the
    // lock-free fast path in `is_cookie_stream` is correct (Acquire/Release pair).
    COOKIE_STREAMS_PRESENT.store(true, Ordering::Release);
    drop(cookie_guard);

    id as *mut c_void
}

// ---------------------------------------------------------------------------
// funopen — BSD callback-based stdio over fopencookie
// ---------------------------------------------------------------------------
//
// `FILE *funopen(const void *cookie,
//                int    (*readfn)(void *, char *, int),
//                int    (*writefn)(void *, const char *, int),
//                fpos_t (*seekfn)(void *, fpos_t, int),
//                int    (*closefn)(void *));`
//
// Differences vs. glibc fopencookie:
//   - read/write fns return int (truncated ssize_t) and take int byte
//     count instead of size_t.
//   - seek fn takes/returns fpos_t (off_t = i64) directly instead of
//     reading/writing through a *mut off64_t pointer.
//   - mode is inferred from which callbacks are NULL, not passed as a
//     separate string. read+write -> "r+", read only -> "r", write only
//     -> "w", both NULL -> EINVAL.
//
// Implementation: heap-allocate a `FunopenTrampoline` struct holding the
// original BSD callbacks plus the user cookie, then build a
// `CookieIoFuncs` with adapter functions that route through the
// trampoline. The trampoline pointer is itself the cookie passed to
// `fopencookie`. The close adapter invokes the user's closefn (if any)
// and then frees the trampoline regardless of its result.

type FunopenReadFn = unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> c_int;
type FunopenWriteFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int;
type FunopenSeekFn = unsafe extern "C" fn(*mut c_void, i64, c_int) -> i64;
type FunopenCloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;

#[repr(C)]
struct FunopenTrampoline {
    cookie: *mut c_void,
    readfn: Option<FunopenReadFn>,
    writefn: Option<FunopenWriteFn>,
    seekfn: Option<FunopenSeekFn>,
    closefn: Option<FunopenCloseFn>,
}

unsafe extern "C" fn funopen_trampoline_read(
    cookie: *mut c_void,
    buf: *mut c_char,
    nbytes: usize,
) -> isize {
    // SAFETY: cookie was set by funopen to a leaked Box<FunopenTrampoline>.
    let tr = unsafe { &*(cookie as *const FunopenTrampoline) };
    let Some(readfn) = tr.readfn else {
        return 0;
    };
    let n = nbytes.min(c_int::MAX as usize) as c_int;
    // SAFETY: buf is valid for `nbytes` bytes per fread/cookie contract.
    let rc = unsafe { readfn(tr.cookie, buf, n) };
    rc as isize
}

unsafe extern "C" fn funopen_trampoline_write(
    cookie: *mut c_void,
    buf: *const c_char,
    nbytes: usize,
) -> isize {
    // SAFETY: cookie was set by funopen to a leaked Box<FunopenTrampoline>.
    let tr = unsafe { &*(cookie as *const FunopenTrampoline) };
    let Some(writefn) = tr.writefn else {
        return 0;
    };
    let n = nbytes.min(c_int::MAX as usize) as c_int;
    // SAFETY: buf is valid for `nbytes` bytes per fwrite/cookie contract.
    let rc = unsafe { writefn(tr.cookie, buf, n) };
    rc as isize
}

unsafe extern "C" fn funopen_trampoline_seek(
    cookie: *mut c_void,
    offset: *mut i64,
    whence: c_int,
) -> c_int {
    // SAFETY: cookie was set by funopen to a leaked Box<FunopenTrampoline>.
    let tr = unsafe { &*(cookie as *const FunopenTrampoline) };
    let Some(seekfn) = tr.seekfn else {
        return -1;
    };
    if offset.is_null() {
        return -1;
    }
    // SAFETY: caller-supplied writable slot per fopencookie contract.
    let req = unsafe { *offset };
    // SAFETY: BSD seek callback signature.
    let result = unsafe { seekfn(tr.cookie, req, whence) };
    if result < 0 {
        return -1;
    }
    // SAFETY: caller-supplied writable slot per fopencookie contract.
    unsafe { *offset = result };
    0
}

unsafe extern "C" fn funopen_trampoline_close(cookie: *mut c_void) -> c_int {
    // SAFETY: cookie was set by funopen to a leaked Box<FunopenTrampoline>;
    // we now reclaim ownership and drop it after the user's closefn runs.
    let tr_box = unsafe { Box::from_raw(cookie as *mut FunopenTrampoline) };
    let rc = if let Some(closefn) = tr_box.closefn {
        // SAFETY: BSD close callback signature.
        unsafe { closefn(tr_box.cookie) }
    } else {
        0
    };
    drop(tr_box);
    rc
}

/// BSD `funopen(cookie, readfn, writefn, seekfn, closefn)` — open a
/// custom FILE backed by user callbacks. See module-level comment for
/// the differences vs. fopencookie. Returns NULL on EINVAL (both
/// readfn and writefn NULL) or allocation failure, with errno set.
///
/// # Safety
///
/// The supplied callbacks must remain valid for the lifetime of the
/// returned stream. `cookie` is passed unmodified as the first
/// argument to each callback.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn funopen(
    cookie: *const c_void,
    readfn: Option<FunopenReadFn>,
    writefn: Option<FunopenWriteFn>,
    seekfn: Option<FunopenSeekFn>,
    closefn: Option<FunopenCloseFn>,
) -> *mut c_void {
    let mode: &CStr = match (readfn.is_some(), writefn.is_some()) {
        (true, true) => c"r+",
        (true, false) => c"r",
        (false, true) => c"w",
        (false, false) => {
            unsafe { set_abi_errno(errno::EINVAL) };
            return std::ptr::null_mut();
        }
    };

    let trampoline = Box::new(FunopenTrampoline {
        cookie: cookie as *mut c_void,
        readfn,
        writefn,
        seekfn,
        closefn,
    });
    let tr_ptr = Box::into_raw(trampoline) as *mut c_void;

    // Build the cookie_io_functions_t adapter.
    let funcs = CookieIoFuncs {
        read: if readfn.is_some() {
            Some(funopen_trampoline_read)
        } else {
            None
        },
        write: if writefn.is_some() {
            Some(funopen_trampoline_write)
        } else {
            None
        },
        seek: if seekfn.is_some() {
            Some(funopen_trampoline_seek)
        } else {
            None
        },
        // Always install the close adapter so the trampoline is freed
        // even when the user supplied no closefn.
        close: Some(funopen_trampoline_close),
    };

    // SAFETY: fopencookie reads `funcs` via *const c_void and copies
    // the struct internally; mode is a static C string.
    let stream = unsafe {
        fopencookie(
            tr_ptr,
            mode.as_ptr(),
            (&funcs as *const CookieIoFuncs) as *const c_void,
        )
    };
    if stream.is_null() {
        // Reclaim and drop the trampoline so we don't leak it.
        // SAFETY: tr_ptr was just produced by Box::into_raw above and
        // hasn't been registered with any fopencookie cookie stream
        // because fopencookie returned NULL.
        let _ = unsafe { Box::from_raw(tr_ptr as *mut FunopenTrampoline) };
        return std::ptr::null_mut();
    }
    stream
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

    let ids: Vec<usize> = {
        let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        sorted_stream_ids(&reg)
    };

    let mut overall_rc = 0;
    for id in ids {
        // `id as *mut c_void` resolves back to the same `id` inside `fclose`
        // because `standard_stream_id` returns `None` for integer values like 1, 2, 3,
        // and `canonical_stream_id` falls back to the integer value.
        let rc = unsafe { fclose(id as *mut c_void) };
        if rc != 0 {
            overall_rc = libc::EOF;
        }
    }
    overall_rc
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

// ---------------------------------------------------------------------------
// fgetln / fpurge (BSD)
// ---------------------------------------------------------------------------
//
// fgetln reads a logical line from `stream` and returns a pointer into a
// thread-local Vec<u8> that stays alive until the next stdio call on the
// same thread. We don't track per-stream lifetimes — the returned pointer
// is valid as long as the caller doesn't trigger another fgetln (or any
// other stdio call that might touch the buffer) on the *current* thread.
//
// fpurge is a thin wrapper over our existing __fpurge that returns int
// (the BSD signature) instead of void (the GNU signature).

#[cfg(feature = "owned-tls-cache")]
static FGETLN_BUFFER_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<Vec<u8>> =
    crate::owned_tls_cache::OwnedTlsCache::new(Vec::new);

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static FGETLN_BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn fgetln_read_into_buffer(stream: *mut c_void, buf: &mut Vec<u8>) -> Option<(*mut c_char, usize)> {
    buf.clear();
    loop {
        // SAFETY: callers pass a non-NULL FILE* validated by the public ABI entrypoint.
        let c = unsafe { fgetc(stream) };
        if c == -1 {
            // EOF or error. If we already have bytes, return them
            // (last line without trailing newline). Otherwise
            // signal end-of-input.
            if buf.is_empty() {
                return None;
            }
            break;
        }
        buf.push(c as u8);
        if c as u8 == b'\n' {
            break;
        }
    }
    // The buffer pointer is `buf.as_mut_ptr()`, but the buffer itself stays
    // owned by the per-thread storage between calls.
    let ptr = buf.as_mut_ptr() as *mut c_char;
    let n = buf.len();
    Some((ptr, n))
}

#[cfg(feature = "owned-tls-cache")]
fn fgetln_current_buffer(stream: *mut c_void) -> Option<(*mut c_char, usize)> {
    FGETLN_BUFFER_OWNED_TLS.with(|buf| fgetln_read_into_buffer(stream, buf))
}

#[cfg(not(feature = "owned-tls-cache"))]
fn fgetln_current_buffer(stream: *mut c_void) -> Option<(*mut c_char, usize)> {
    FGETLN_BUFFER.with(|cell| {
        let mut buf = cell.borrow_mut();
        fgetln_read_into_buffer(stream, &mut buf)
    })
}

/// BSD `fgetln(stream, *len)` — read a line from `stream` (up to and
/// including the trailing `\n`) and return a pointer into a
/// thread-local buffer plus the line length via `*len`. Returns NULL
/// on EOF (with `*len = 0`) or on read error.
///
/// The returned pointer remains valid until the next `fgetln` call on
/// the same thread. Callers MUST NOT modify or `free()` it.
///
/// # Safety
///
/// `stream` must be a valid `FILE *`. `len`, when non-NULL, must
/// point to writable `size_t` storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetln(stream: *mut c_void, len: *mut usize) -> *mut c_char {
    if stream.is_null() {
        if !len.is_null() {
            // SAFETY: caller-supplied writable slot.
            unsafe { *len = 0 };
        }
        return std::ptr::null_mut();
    }

    let result = fgetln_current_buffer(stream);

    match result {
        Some((ptr, n)) => {
            if !len.is_null() {
                // SAFETY: caller-supplied writable slot.
                unsafe { *len = n };
            }
            ptr
        }
        None => {
            if !len.is_null() {
                // SAFETY: caller-supplied writable slot.
                unsafe { *len = 0 };
            }
            std::ptr::null_mut()
        }
    }
}

/// BSD `fpurge(stream)` — discard any pending input or unwritten
/// output buffered on `stream`. Returns 0 on success, EOF on error.
///
/// Internally delegates to the GNU `__fpurge` no-op stub (we don't
/// keep our own buffer). The return value is therefore always 0
/// when `stream` is non-NULL, matching glibc's `__fpurge` (which
/// signals failure only via `ferror`).
///
/// # Safety
///
/// `stream`, when non-NULL, must be a valid `FILE *`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fpurge(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        // BSD spec: NULL stream is undefined; we choose to return EOF.
        return -1;
    }
    // SAFETY: __fpurge delegates to the GNU stub which is itself a no-op
    // for non-FILE buffers (we don't own the FILE buffer).
    unsafe { crate::glibc_internal_abi::__fpurge(stream) };
    0
}

// ---------------------------------------------------------------------------
// fparseln (NetBSD libutil logical-line reader)
// ---------------------------------------------------------------------------
//
// Drives our own fgetc loop to assemble physical lines, then folds them
// through frankenlibc_core::stdio::fparseln per the libutil grammar.
// Returns a malloc'd C string the caller must free().

const FPARSELN_DEFAULT_DELIM: [u8; 3] = *b"\\\n#";

/// NetBSD libutil `fparseln(stream, *len, *lineno, delim, flags)` —
/// read a logical line from `stream`, handling backslash
/// continuation, comments, and escape sequences per the
/// `frankenlibc_core::stdio::fparseln` rules. Returns a
/// freshly-`malloc`-allocated NUL-terminated string the caller is
/// responsible for freeing, or NULL on EOF / read error.
///
/// `delim`, when non-NULL, is a 3-byte array `[escape, separator,
/// comment]`. NULL selects the documented defaults `['\\', '\n', '#']`.
///
/// `*len` (when non-NULL) is set to the length of the returned
/// string excluding the trailing NUL. `*lineno` (when non-NULL) is
/// incremented by the number of physical lines consumed.
///
/// # Safety
///
/// `stream` must be a valid `FILE *`. `len`/`lineno`/`delim`, when
/// non-NULL, must point to writable storage of the appropriate type.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fparseln(
    stream: *mut c_void,
    len: *mut usize,
    lineno: *mut usize,
    delim: *const c_char,
    flags: c_int,
) -> *mut c_char {
    if stream.is_null() {
        if !len.is_null() {
            unsafe { *len = 0 };
        }
        return std::ptr::null_mut();
    }

    let delim_bytes = if delim.is_null() {
        FPARSELN_DEFAULT_DELIM
    } else {
        // SAFETY: caller-supplied 3-byte array.
        unsafe { [*delim as u8, *delim.add(1) as u8, *delim.add(2) as u8] }
    };

    let mut out_buf: Vec<u8> = Vec::new();
    let mut consumed_any_line = false;
    let mut lines_consumed: usize = 0;

    loop {
        // Read one physical line via fgetc until separator or EOF.
        let mut phys: Vec<u8> = Vec::new();
        let mut hit_eof_immediately = true;
        loop {
            // SAFETY: stream is a valid FILE* per caller.
            let c = unsafe { fgetc(stream) };
            if c == -1 {
                break;
            }
            hit_eof_immediately = false;
            phys.push(c as u8);
            if c as u8 == delim_bytes[1] {
                break;
            }
        }
        if hit_eof_immediately && !consumed_any_line {
            // True EOF on the very first read of this fparseln call.
            if !len.is_null() {
                unsafe { *len = 0 };
            }
            return std::ptr::null_mut();
        }
        consumed_any_line = true;
        lines_consumed += 1;

        let outcome = frankenlibc_core::stdio::fparseln::fold_line(
            &phys,
            &mut out_buf,
            delim_bytes,
            flags as u32,
        );
        if matches!(
            outcome,
            frankenlibc_core::stdio::fparseln::FoldOutcome::Done
        ) {
            break;
        }
        // Continuation: loop and read the next physical line.
        if hit_eof_immediately {
            break;
        }
    }

    if !lineno.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *lineno = (*lineno).wrapping_add(lines_consumed) };
    }

    // Allocate via malloc so the caller can free() per BSD contract.
    let n = out_buf.len();
    let raw = unsafe { crate::malloc_abi::malloc(n + 1) } as *mut c_char;
    if raw.is_null() {
        if !len.is_null() {
            unsafe { *len = 0 };
        }
        return std::ptr::null_mut();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(out_buf.as_ptr(), raw as *mut u8, n);
        *raw.add(n) = 0;
    }
    if !len.is_null() {
        unsafe { *len = n };
    }
    raw
}

// ---------------------------------------------------------------------------
// strvis / strnvis / strunvis / strnunvis (NetBSD vis(3) family)
// ---------------------------------------------------------------------------

unsafe fn bounded_c_str_bytes<'a>(ptr: *const c_char) -> Option<&'a [u8]> {
    let (len, terminated) = unsafe { scan_c_str_len(ptr, None) };
    if !terminated {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) })
}

/// NetBSD `strvis(dst, src, flags)` — encode `src` into `dst` per
/// the vis(3) byte transformation. Returns the number of bytes
/// written excluding the trailing NUL.
///
/// # Safety
///
/// Caller must ensure `src` is a valid NUL-terminated C string and
/// `dst` is large enough (worst case 4 × strlen(src) + 1).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strvis(dst: *mut c_char, src: *const c_char, flags: c_int) -> c_int {
    if dst.is_null() || src.is_null() {
        return -1;
    }
    let Some(bytes) = (unsafe { bounded_c_str_bytes(src) }) else {
        return -1;
    };
    let encoded = frankenlibc_core::stdio::vis::strvis_to_vec(bytes, flags as u32);
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), dst as *mut u8, encoded.len());
        *dst.add(encoded.len()) = 0;
    }
    encoded.len() as c_int
}

/// NetBSD `strnvis(dst, dlen, src, flags)` — bounded variant of
/// [`strvis`]. Returns encoded length on success or -1 if `dst`
/// would overflow (the prefix that fits is still NUL-terminated).
///
/// # Safety
///
/// Same as [`strvis`] but `dst` need only have `dlen` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strnvis(
    dst: *mut c_char,
    dlen: usize,
    src: *const c_char,
    flags: c_int,
) -> c_int {
    if dst.is_null() || src.is_null() || dlen == 0 {
        return -1;
    }
    let Some(bytes) = (unsafe { bounded_c_str_bytes(src) }) else {
        return -1;
    };
    let encoded = frankenlibc_core::stdio::vis::strvis_to_vec(bytes, flags as u32);
    if encoded.len() < dlen {
        unsafe {
            std::ptr::copy_nonoverlapping(encoded.as_ptr(), dst as *mut u8, encoded.len());
            *dst.add(encoded.len()) = 0;
        }
        encoded.len() as c_int
    } else {
        let copy_len = dlen - 1;
        unsafe {
            std::ptr::copy_nonoverlapping(encoded.as_ptr(), dst as *mut u8, copy_len);
            *dst.add(copy_len) = 0;
        }
        -1
    }
}

/// NetBSD `strunvis(dst, src)` — decode `src` into `dst`. Returns
/// the number of decoded bytes (excluding NUL) or -1 on malformed
/// input.
///
/// # Safety
///
/// Caller must ensure `src` is a valid NUL-terminated C string and
/// `dst` is at least `strlen(src) + 1` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strunvis(dst: *mut c_char, src: *const c_char) -> c_int {
    if dst.is_null() || src.is_null() {
        return -1;
    }
    let Some(bytes) = (unsafe { bounded_c_str_bytes(src) }) else {
        return -1;
    };
    let decoded = match frankenlibc_core::stdio::vis::strunvis_to_vec(bytes) {
        Some(v) => v,
        None => return -1,
    };
    unsafe {
        std::ptr::copy_nonoverlapping(decoded.as_ptr(), dst as *mut u8, decoded.len());
        *dst.add(decoded.len()) = 0;
    }
    decoded.len() as c_int
}

/// NetBSD `strnunvis(dst, dlen, src)` — bounded variant of
/// [`strunvis`]. Returns decoded length or -1 on malformed input
/// or buffer too small.
///
/// # Safety
///
/// Same as [`strunvis`] but `dst` need only have `dlen` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strnunvis(dst: *mut c_char, dlen: usize, src: *const c_char) -> c_int {
    if dst.is_null() || src.is_null() || dlen == 0 {
        return -1;
    }
    let Some(bytes) = (unsafe { bounded_c_str_bytes(src) }) else {
        return -1;
    };
    let decoded = match frankenlibc_core::stdio::vis::strunvis_to_vec(bytes) {
        Some(v) => v,
        None => return -1,
    };
    if decoded.len() + 1 > dlen {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(decoded.as_ptr(), dst as *mut u8, decoded.len());
        *dst.add(decoded.len()) = 0;
    }
    decoded.len() as c_int
}

// ---------------------------------------------------------------------------
// vis / nvis (NetBSD vis(3) single-byte encoders)
// ---------------------------------------------------------------------------

/// NetBSD `vis(dst, c, flags, nextc)` — encode the single byte `c`
/// into `dst` (NUL-terminated), returning a pointer to the trailing
/// NUL. `nextc` is used by `VIS_CSTYLE` to avoid ambiguous `\0`
/// before an octal digit.
///
/// Returns NULL when `dst` is NULL.
///
/// # Safety
///
/// Caller must ensure `dst` is large enough for the worst-case
/// encoded byte (7 bytes for `\M-\000`) plus the trailing NUL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vis(
    dst: *mut c_char,
    c: c_int,
    flags: c_int,
    nextc: c_int,
) -> *mut c_char {
    if dst.is_null() {
        return std::ptr::null_mut();
    }
    let mut buf: Vec<u8> = Vec::with_capacity(8);
    frankenlibc_core::stdio::vis::encode_byte_with_next(
        c as u8,
        flags as u32,
        Some(nextc as u8),
        &mut buf,
    );
    // SAFETY: caller-supplied dst has room for the worst-case
    // encoded byte (max 7 bytes + NUL).
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), dst as *mut u8, buf.len());
        *dst.add(buf.len()) = 0;
        dst.add(buf.len())
    }
}

/// NetBSD `nvis(dst, dlen, c, flags, nextc)` — bounded variant of
/// [`vis`]. Returns NULL on overflow (encoded form + NUL exceeds
/// `dlen`) without writing anything; otherwise writes and returns a
/// pointer to the trailing NUL.
///
/// # Safety
///
/// Caller must ensure `dst` is valid for `dlen` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nvis(
    dst: *mut c_char,
    dlen: usize,
    c: c_int,
    flags: c_int,
    nextc: c_int,
) -> *mut c_char {
    if dst.is_null() || dlen == 0 {
        return std::ptr::null_mut();
    }
    let mut buf: Vec<u8> = Vec::with_capacity(8);
    frankenlibc_core::stdio::vis::encode_byte_with_next(
        c as u8,
        flags as u32,
        Some(nextc as u8),
        &mut buf,
    );
    if buf.len() + 1 > dlen {
        return std::ptr::null_mut();
    }
    // SAFETY: caller-supplied dst has dlen writable bytes; we just
    // confirmed buf.len()+1 fits.
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), dst as *mut u8, buf.len());
        *dst.add(buf.len()) = 0;
        dst.add(buf.len())
    }
}

// ---------------------------------------------------------------------------
// strvisx / strnvisx / strunvisx / strnunvisx (NetBSD vis(3) extended length)
// ---------------------------------------------------------------------------

/// NetBSD `strvisx(dst, src, srclen, flags)` — encode the first
/// `srclen` bytes of `src` (may contain embedded NULs) into `dst`.
/// Returns the encoded length excluding the trailing NUL, or -1 on
/// NULL input.
///
/// # Safety
///
/// `dst` must hold at least 4 × srclen + 1 writable bytes (the
/// worst-case encoded length). `src` must be valid for `srclen`
/// readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strvisx(
    dst: *mut c_char,
    src: *const c_char,
    srclen: usize,
    flags: c_int,
) -> c_int {
    if dst.is_null() || (src.is_null() && srclen != 0) {
        return -1;
    }
    let bytes: &[u8] = if srclen == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(src as *const u8, srclen) }
    };
    let encoded = frankenlibc_core::stdio::vis::strvis_to_vec(bytes, flags as u32);
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), dst as *mut u8, encoded.len());
        *dst.add(encoded.len()) = 0;
    }
    encoded.len() as c_int
}

/// NetBSD `strnvisx(dst, dlen, src, srclen, flags)` — bounded
/// variant of [`strvisx`]. Returns the encoded length on success;
/// returns -1 when the encoded form + NUL exceeds `dlen` (the
/// prefix that fits is still NUL-terminated).
///
/// # Safety
///
/// Same as [`strvisx`] but `dst` need only have `dlen` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strnvisx(
    dst: *mut c_char,
    dlen: usize,
    src: *const c_char,
    srclen: usize,
    flags: c_int,
) -> c_int {
    if dst.is_null() || (src.is_null() && srclen != 0) || dlen == 0 {
        return -1;
    }
    let bytes: &[u8] = if srclen == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(src as *const u8, srclen) }
    };
    let encoded = frankenlibc_core::stdio::vis::strvis_to_vec(bytes, flags as u32);
    if encoded.len() < dlen {
        unsafe {
            std::ptr::copy_nonoverlapping(encoded.as_ptr(), dst as *mut u8, encoded.len());
            *dst.add(encoded.len()) = 0;
        }
        encoded.len() as c_int
    } else {
        let copy_len = dlen - 1;
        unsafe {
            std::ptr::copy_nonoverlapping(encoded.as_ptr(), dst as *mut u8, copy_len);
            *dst.add(copy_len) = 0;
        }
        -1
    }
}

/// NetBSD `strunvisx(dst, src, flags)` — decode `src` (NUL-terminated
/// vis-encoded ASCII) into `dst`. Accepts `flags` for libutil API
/// compat; current decoder is mode-agnostic so the parameter has no
/// effect.
///
/// # Safety
///
/// Caller must ensure `src` is a valid NUL-terminated C string and
/// `dst` is at least `strlen(src) + 1` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strunvisx(dst: *mut c_char, src: *const c_char, _flags: c_int) -> c_int {
    if dst.is_null() || src.is_null() {
        return -1;
    }
    let Some(bytes) = (unsafe { bounded_c_str_bytes(src) }) else {
        return -1;
    };
    let decoded = match frankenlibc_core::stdio::vis::strunvis_to_vec(bytes) {
        Some(v) => v,
        None => return -1,
    };
    unsafe {
        std::ptr::copy_nonoverlapping(decoded.as_ptr(), dst as *mut u8, decoded.len());
        *dst.add(decoded.len()) = 0;
    }
    decoded.len() as c_int
}

/// NetBSD `strnunvisx(dst, dlen, src, flags)` — bounded variant of
/// [`strunvisx`]. Returns -1 on malformed input or when the decoded
/// form + NUL exceeds `dlen`.
///
/// # Safety
///
/// Same as [`strunvisx`] but `dst` need only have `dlen` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strnunvisx(
    dst: *mut c_char,
    dlen: usize,
    src: *const c_char,
    _flags: c_int,
) -> c_int {
    if dst.is_null() || src.is_null() || dlen == 0 {
        return -1;
    }
    let Some(bytes) = (unsafe { bounded_c_str_bytes(src) }) else {
        return -1;
    };
    let decoded = match frankenlibc_core::stdio::vis::strunvis_to_vec(bytes) {
        Some(v) => v,
        None => return -1,
    };
    if decoded.len() + 1 > dlen {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(decoded.as_ptr(), dst as *mut u8, decoded.len());
        *dst.add(decoded.len()) = 0;
    }
    decoded.len() as c_int
}

// ---------------------------------------------------------------------------
// unvis (NetBSD vis(3) streaming byte decoder)
// ---------------------------------------------------------------------------
//
// The C ABI threads decoder state through an opaque `int *astate`
// cell. We round-trip the full UnvisDecoder state through that cell
// using `UnvisDecoder::save_state` / `from_saved_state` so the
// streaming machine can continue across successive calls without
// allocating.

const UNVIS_VALID: c_int = 1;
const UNVIS_VALIDPUSH: c_int = 2;
const UNVIS_NOCHAR: c_int = 3;
const UNVIS_SYNBAD: c_int = -1;
const UNVIS_END_VAL: c_int = 0;
const UNVIS_END_FLAG: c_int = 1; // libutil's UNVIS_END flag

fn step_outcome(
    cp: *mut c_char,
    dec: &mut frankenlibc_core::stdio::vis::UnvisDecoder,
    outcome: frankenlibc_core::stdio::vis::UnvisOutcome,
) -> c_int {
    use frankenlibc_core::stdio::vis::UnvisOutcome as O;
    match outcome {
        O::Valid(b) => {
            if !cp.is_null() {
                unsafe { *cp = b as c_char };
            }
            UNVIS_VALID
        }
        O::ValidPush(b) => {
            if !cp.is_null() {
                unsafe { *cp = b as c_char };
            }
            UNVIS_VALIDPUSH
        }
        O::NoChar => UNVIS_NOCHAR,
        O::Bad => {
            dec.reset();
            UNVIS_SYNBAD
        }
        O::End => UNVIS_END_VAL,
    }
}

/// NetBSD `unvis(cp, c, astate, flag)` — streaming single-byte
/// decoder. Caller feeds bytes one at a time, threading the opaque
/// `*astate` (a single int round-tripped through
/// [`UnvisDecoder::save_state`]). Returns one of:
///
/// * `UNVIS_VALID` (1) — `*cp` holds a fully decoded byte.
/// * `UNVIS_VALIDPUSH` (2) — `*cp` is decoded; re-feed the current
///   input byte.
/// * `UNVIS_NOCHAR` (3) — partial sequence, keep feeding.
/// * `UNVIS_SYNBAD` (-1) — malformed input.
/// * `0` — terminal (call with `flag = UNVIS_END = 1` after the last
///   input byte to flush state).
///
/// # Safety
///
/// `astate` must point to a writable `c_int` that survives across
/// successive calls. `cp`, when non-NULL, must point to a writable
/// `c_char`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn unvis(
    cp: *mut c_char,
    c: c_int,
    astate: *mut c_int,
    flag: c_int,
) -> c_int {
    use frankenlibc_core::stdio::vis::UnvisDecoder;

    if astate.is_null() {
        return UNVIS_SYNBAD;
    }

    let packed = unsafe { *astate } as u32;
    let mut dec = UnvisDecoder::from_saved_state(packed);

    if flag & UNVIS_END_FLAG != 0 {
        let outcome = dec.feed_end();
        let result = step_outcome(cp, &mut dec, outcome);
        unsafe {
            *astate = dec.save_state() as c_int;
        }
        return result;
    }

    let outcome = dec.feed(c as u8);
    let result = step_outcome(cp, &mut dec, outcome);
    unsafe {
        *astate = dec.save_state() as c_int;
    }
    result
}

// ---------------------------------------------------------------------------
// svis / snvis / strsvis / strsnvis / strsvisx / strsnvisx
// (NetBSD vis(3) extra-bytes family)
// ---------------------------------------------------------------------------

/// Read the NUL-terminated `extra` argument shared by the svis(3)
/// family. Returns an empty slice for NULL and `None` when a tracked
/// non-NULL string has no terminator inside its allocation.
unsafe fn extras_slice<'a>(extra: *const c_char) -> Option<&'a [u8]> {
    if extra.is_null() {
        return Some(&[]);
    }
    unsafe { bounded_c_str_bytes(extra) }
}

/// NetBSD `svis(dst, c, flags, nextc, extra)` — sibling of [`vis`]
/// that additionally treats every byte in the NUL-terminated `extra`
/// string as needing escape. Writes encoded bytes followed by NUL,
/// returns a pointer to the trailing NUL.
///
/// # Safety
///
/// Caller must ensure `dst` has room for the encoded form plus NUL
/// (worst case 5 bytes). `extra`, when non-NULL, must point to a
/// NUL-terminated byte string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn svis(
    dst: *mut c_char,
    c: c_int,
    flags: c_int,
    nextc: c_int,
    extra: *const c_char,
) -> *mut c_char {
    if dst.is_null() {
        return std::ptr::null_mut();
    }
    let Some(extras) = (unsafe { extras_slice(extra) }) else {
        return std::ptr::null_mut();
    };
    let mut buf: Vec<u8> = Vec::with_capacity(8);
    frankenlibc_core::stdio::vis::encode_byte_with_extra_and_next(
        c as u8,
        flags as u32,
        Some(nextc as u8),
        extras,
        &mut buf,
    );
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), dst as *mut u8, buf.len());
        *dst.add(buf.len()) = 0;
        dst.add(buf.len())
    }
}

/// NetBSD `snvis(dst, dlen, c, flags, nextc, extra)` — bounded
/// variant of [`svis`]. Returns NULL on overflow without writing
/// anything; otherwise writes encoded bytes + NUL and returns a
/// pointer to the trailing NUL.
///
/// # Safety
///
/// Caller must ensure `dst` is valid for `dlen` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn snvis(
    dst: *mut c_char,
    dlen: usize,
    c: c_int,
    flags: c_int,
    nextc: c_int,
    extra: *const c_char,
) -> *mut c_char {
    if dst.is_null() || dlen == 0 {
        return std::ptr::null_mut();
    }
    let Some(extras) = (unsafe { extras_slice(extra) }) else {
        return std::ptr::null_mut();
    };
    let mut buf: Vec<u8> = Vec::with_capacity(8);
    frankenlibc_core::stdio::vis::encode_byte_with_extra_and_next(
        c as u8,
        flags as u32,
        Some(nextc as u8),
        extras,
        &mut buf,
    );
    if buf.len() + 1 > dlen {
        return std::ptr::null_mut();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), dst as *mut u8, buf.len());
        *dst.add(buf.len()) = 0;
        dst.add(buf.len())
    }
}

/// NetBSD `strsvis(dst, src, flags, extra)` — sibling of [`strvis`]
/// that treats every byte in `extra` as needing escape. Returns the
/// encoded length excluding the trailing NUL, or -1 on NULL `dst` /
/// `src`.
///
/// # Safety
///
/// `dst` must hold at least 4 × strlen(src) + 1 writable bytes.
/// `src` and `extra` (when non-NULL) must be NUL-terminated.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strsvis(
    dst: *mut c_char,
    src: *const c_char,
    flags: c_int,
    extra: *const c_char,
) -> c_int {
    if dst.is_null() || src.is_null() {
        return -1;
    }
    let Some(src_slice) = (unsafe { bounded_c_str_bytes(src) }) else {
        return -1;
    };
    let Some(extras) = (unsafe { extras_slice(extra) }) else {
        return -1;
    };
    let encoded =
        frankenlibc_core::stdio::vis::strvis_to_vec_with_extra(src_slice, flags as u32, extras);
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), dst as *mut u8, encoded.len());
        *dst.add(encoded.len()) = 0;
    }
    encoded.len() as c_int
}

/// NetBSD `strsnvis(dst, dlen, src, flags, extra)` — bounded variant
/// of [`strsvis`]. Returns the encoded length on success or -1 on
/// overflow / NULL input. On overflow no bytes are written.
///
/// # Safety
///
/// Same as [`strsvis`] but `dst` need only have `dlen` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strsnvis(
    dst: *mut c_char,
    dlen: usize,
    src: *const c_char,
    flags: c_int,
    extra: *const c_char,
) -> c_int {
    if dst.is_null() || src.is_null() || dlen == 0 {
        return -1;
    }
    let Some(src_slice) = (unsafe { bounded_c_str_bytes(src) }) else {
        return -1;
    };
    let Some(extras) = (unsafe { extras_slice(extra) }) else {
        return -1;
    };
    let encoded =
        frankenlibc_core::stdio::vis::strvis_to_vec_with_extra(src_slice, flags as u32, extras);
    if encoded.len() + 1 > dlen {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), dst as *mut u8, encoded.len());
        *dst.add(encoded.len()) = 0;
    }
    encoded.len() as c_int
}

/// NetBSD `strsvisx(dst, src, srclen, flags, extra)` — extended
/// length variant of [`strsvis`] that accepts embedded NULs in
/// `src`. Returns encoded length excluding trailing NUL, or -1 on
/// NULL input.
///
/// # Safety
///
/// `dst` must hold at least 4 × srclen + 1 writable bytes. `src`
/// must be valid for `srclen` readable bytes. `extra`, when non-NULL,
/// must be NUL-terminated.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strsvisx(
    dst: *mut c_char,
    src: *const c_char,
    srclen: usize,
    flags: c_int,
    extra: *const c_char,
) -> c_int {
    if dst.is_null() || (src.is_null() && srclen != 0) {
        return -1;
    }
    let src_slice: &[u8] = if srclen == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(src as *const u8, srclen) }
    };
    let Some(extras) = (unsafe { extras_slice(extra) }) else {
        return -1;
    };
    let encoded =
        frankenlibc_core::stdio::vis::strvis_to_vec_with_extra(src_slice, flags as u32, extras);
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), dst as *mut u8, encoded.len());
        *dst.add(encoded.len()) = 0;
    }
    encoded.len() as c_int
}

/// NetBSD `strsnvisx(dst, dlen, src, srclen, flags, extra)` —
/// bounded variant of [`strsvisx`]. Returns encoded length on
/// success or -1 on overflow / NULL input. On overflow no bytes are
/// written.
///
/// # Safety
///
/// Same as [`strsvisx`] but `dst` need only have `dlen` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strsnvisx(
    dst: *mut c_char,
    dlen: usize,
    src: *const c_char,
    srclen: usize,
    flags: c_int,
    extra: *const c_char,
) -> c_int {
    if dst.is_null() || (src.is_null() && srclen != 0) || dlen == 0 {
        return -1;
    }
    let src_slice: &[u8] = if srclen == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(src as *const u8, srclen) }
    };
    let Some(extras) = (unsafe { extras_slice(extra) }) else {
        return -1;
    };
    let encoded =
        frankenlibc_core::stdio::vis::strvis_to_vec_with_extra(src_slice, flags as u32, extras);
    if encoded.len() + 1 > dlen {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), dst as *mut u8, encoded.len());
        *dst.add(encoded.len()) = 0;
    }
    encoded.len() as c_int
}

// ---------------------------------------------------------------------------
// stravis (NetBSD allocating strvis)
// ---------------------------------------------------------------------------

/// NetBSD `stravis(outp, src, flags)` — allocate an output buffer
/// large enough to hold the encoded form of `src`, fill it via
/// [`strvis`], and store the pointer in `*outp`. Returns the encoded
/// length (excluding the trailing NUL) on success, or -1 on NULL
/// inputs / allocation failure. The caller is responsible for
/// `free()`ing `*outp`.
///
/// # Safety
///
/// `outp`, when non-NULL, must point to a writable `*mut c_char`
/// cell. `src` must be NUL-terminated.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn stravis(
    outp: *mut *mut c_char,
    src: *const c_char,
    flags: c_int,
) -> c_int {
    if outp.is_null() || src.is_null() {
        return -1;
    }
    let Some(bytes) = (unsafe { bounded_c_str_bytes(src) }) else {
        return -1;
    };
    let encoded = frankenlibc_core::stdio::vis::strvis_to_vec(bytes, flags as u32);
    let needed = encoded.len() + 1;
    let buf = unsafe { crate::malloc_abi::malloc(needed) } as *mut c_char;
    if buf.is_null() {
        unsafe { *outp = std::ptr::null_mut() };
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), buf as *mut u8, encoded.len());
        *buf.add(encoded.len()) = 0;
        *outp = buf;
    }
    encoded.len() as c_int
}

// ---------------------------------------------------------------------------
// strnvis_netbsd / strnunvis_netbsd
//
// libbsd ships these as namespaced aliases for callers that want to
// disambiguate against the FreeBSD/glibc `strnvis(dst, src, dlen,
// flags)` argument order. Our existing `strnvis` and `strnunvis`
// already use the NetBSD `(dst, dlen, src, ...)` order, so the
// `_netbsd` aliases delegate directly.
// ---------------------------------------------------------------------------

/// libbsd `strnvis_netbsd(dst, dlen, src, flags)` — direct alias of
/// our NetBSD-order [`strnvis`].
///
/// # Safety
///
/// Same as [`strnvis`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strnvis_netbsd(
    dst: *mut c_char,
    dlen: usize,
    src: *const c_char,
    flags: c_int,
) -> c_int {
    unsafe { strnvis(dst, dlen, src, flags) }
}

/// libbsd `strnunvis_netbsd(dst, dlen, src)` — direct alias of our
/// NetBSD-order [`strnunvis`].
///
/// # Safety
///
/// Same as [`strnunvis`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strnunvis_netbsd(
    dst: *mut c_char,
    dlen: usize,
    src: *const c_char,
) -> c_int {
    unsafe { strnunvis(dst, dlen, src) }
}

// ---------------------------------------------------------------------------
// strenvisx / strsenvisx (NetBSD env-aware vis(3) variants)
// ---------------------------------------------------------------------------

/// Read the `VIS_OPTIONS` env var (if set) and return the OR of the
/// flag bits it names. Empty / unset env returns 0.
fn vis_options_from_env() -> u32 {
    let key = c"VIS_OPTIONS";
    let val_ptr = unsafe { crate::stdlib_abi::getenv(key.as_ptr()) };
    if val_ptr.is_null() {
        return 0;
    }
    let (len, terminated) = unsafe { scan_c_str_len(val_ptr, None) };
    if !terminated {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(val_ptr.cast::<u8>(), len) };
    frankenlibc_core::stdio::vis::parse_vis_options(bytes)
}

/// NetBSD `strenvisx(dst, src, srclen, flags, cerr_ptr)` — extended
/// strvisx that ORs in any `VIS_*` bits parsed from the
/// `VIS_OPTIONS` environment variable, then encodes `srclen` bytes
/// of `src` into `dst`. Writes 0 to `*cerr_ptr` (always — our
/// byte-stream encoder never raises a character-set error).
/// Returns the encoded length excluding NUL, or -1 on NULL inputs.
///
/// # Safety
///
/// `dst` must hold at least `4 * srclen + 1` writable bytes. `src`
/// must be valid for `srclen` readable bytes. `cerr_ptr`, when
/// non-NULL, must be writable.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strenvisx(
    dst: *mut c_char,
    src: *const c_char,
    srclen: usize,
    flags: c_int,
    cerr_ptr: *mut c_int,
) -> c_int {
    if dst.is_null() || (src.is_null() && srclen != 0) {
        return -1;
    }
    let merged_flags = (flags as u32) | vis_options_from_env();
    let src_slice: &[u8] = if srclen == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(src as *const u8, srclen) }
    };
    let encoded = frankenlibc_core::stdio::vis::strvis_to_vec(src_slice, merged_flags);
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), dst as *mut u8, encoded.len());
        *dst.add(encoded.len()) = 0;
    }
    if !cerr_ptr.is_null() {
        unsafe { *cerr_ptr = 0 };
    }
    encoded.len() as c_int
}

/// NetBSD `strsenvisx(dst, dlen, src, srclen, flags, extra,
/// cerr_ptr)` — bounded extended strsvisx that combines the
/// extras-bytes contract of [`strsvisx`] with the env-var flag
/// merge of [`strenvisx`]. Writes 0 to `*cerr_ptr`. Returns the
/// encoded length on success or -1 on overflow / NULL input. On
/// overflow no bytes are written.
///
/// # Safety
///
/// Same as [`strenvisx`] but `dst` need only have `dlen` bytes.
/// `extra`, when non-NULL, must be NUL-terminated.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strsenvisx(
    dst: *mut c_char,
    dlen: usize,
    src: *const c_char,
    srclen: usize,
    flags: c_int,
    extra: *const c_char,
    cerr_ptr: *mut c_int,
) -> c_int {
    if dst.is_null() || (src.is_null() && srclen != 0) || dlen == 0 {
        return -1;
    }
    let merged_flags = (flags as u32) | vis_options_from_env();
    let src_slice: &[u8] = if srclen == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(src as *const u8, srclen) }
    };
    let Some(extras) = (unsafe { extras_slice(extra) }) else {
        return -1;
    };
    let encoded =
        frankenlibc_core::stdio::vis::strvis_to_vec_with_extra(src_slice, merged_flags, extras);
    if encoded.len() + 1 > dlen {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), dst as *mut u8, encoded.len());
        *dst.add(encoded.len()) = 0;
    }
    if !cerr_ptr.is_null() {
        unsafe { *cerr_ptr = 0 };
    }
    encoded.len() as c_int
}

// ---------------------------------------------------------------------------
// snprintb / snprintb_m (BSD libutil bit-name formatter)
// ---------------------------------------------------------------------------

/// Internal helper: copy the rendered bytes into the caller-supplied
/// bounded buffer per snprintf(3) semantics. Returns the full
/// rendered length (excluding the NUL) regardless of truncation.
unsafe fn snprintb_write_bounded(buf: *mut c_char, bufsize: usize, rendered: &[u8]) -> c_int {
    if buf.is_null() || bufsize == 0 {
        return rendered.len() as c_int;
    }
    let cap = bufsize.saturating_sub(1);
    let n = rendered.len().min(cap);
    unsafe {
        std::ptr::copy_nonoverlapping(rendered.as_ptr(), buf as *mut u8, n);
        *buf.add(n) = 0;
    }
    rendered.len() as c_int
}

/// BSD `snprintb(buf, bufsize, fmt, val)` — render `val` according
/// to the BSD bit-name format string `fmt` into `buf`. Output looks
/// like `"0x3<FOO,BAR>"` for a hex base with named bits set.
/// Returns the full rendered length (excluding NUL); truncates to
/// `bufsize` if necessary, just like `snprintf(3)`.
///
/// # Safety
///
/// `buf`, when non-NULL, must be valid for `bufsize` writable
/// bytes. `fmt` must be NUL-terminated.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn snprintb(
    buf: *mut c_char,
    bufsize: usize,
    fmt: *const c_char,
    val: u64,
) -> c_int {
    if fmt.is_null() {
        return -1;
    }
    let Some(fmt_bytes) = (unsafe { bounded_c_str_bytes(fmt) }) else {
        return -1;
    };
    let rendered = frankenlibc_core::stdio::snprintb::format_snprintb(fmt_bytes, val);
    unsafe { snprintb_write_bounded(buf, bufsize, &rendered) }
}

/// BSD `snprintb_m(buf, bufsize, fmt, val, max_per_line)` — like
/// [`snprintb`] but inserts newline-separated continuation lines
/// (re-emitting the base+value prefix) so no rendered line exceeds
/// `max_per_line` bytes. `max_per_line == 0` falls back to
/// single-line behavior.
///
/// # Safety
///
/// Same as [`snprintb`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn snprintb_m(
    buf: *mut c_char,
    bufsize: usize,
    fmt: *const c_char,
    val: u64,
    max_per_line: usize,
) -> c_int {
    if fmt.is_null() {
        return -1;
    }
    let Some(fmt_bytes) = (unsafe { bounded_c_str_bytes(fmt) }) else {
        return -1;
    };
    let rendered =
        frankenlibc_core::stdio::snprintb::format_snprintb_m(fmt_bytes, val, max_per_line);
    unsafe { snprintb_write_bounded(buf, bufsize, &rendered) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdio_stream_id_hasher_integer_fast_path_matches_usize_and_u64() {
        let value = 0x1000_0100usize;

        let mut via_usize = StreamIdHasher::default();
        via_usize.write_usize(value);

        let mut via_u64 = StreamIdHasher::default();
        via_u64.write_u64(value as u64);

        let mut via_bytes = StreamIdHasher::default();
        via_bytes.write(&value.to_ne_bytes());

        assert_eq!(via_usize.finish(), via_u64.finish());
        assert_ne!(via_usize.finish(), via_bytes.finish());
    }

    #[test]
    fn stdio_flush_all_id_snapshot_is_sorted() {
        let mut reg = StreamRegistry::new();
        let writable = OpenFlags {
            writable: true,
            ..Default::default()
        };

        reg.streams
            .insert(0x1000_0040, StdioStream::new(-1, writable));
        reg.insert_stream(
            0x1000_0020,
            StdioStream::new(
                -1,
                OpenFlags {
                    writable: true,
                    ..Default::default()
                },
            ),
        );

        let ids = sorted_stream_ids(&reg);
        assert!(ids.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(ids.starts_with(&[STDIN_SENTINEL, STDOUT_SENTINEL, STDERR_SENTINEL]));
    }

    #[test]
    fn printf_direct_payload_classifies_string_newline_only_for_nonnull_s() {
        let text = b"status=ok\0";
        let args = [text.as_ptr() as u64];

        let payload = unsafe { direct_printf_string_payload(b"%s\n", args.as_ptr(), 1) };
        match payload {
            Some(DirectPrintfPayload::StringNewline(bytes)) => assert_eq!(bytes, b"status=ok"),
            _ => panic!("expected direct %s newline payload"),
        }

        let null_args = [0u64];
        assert!(unsafe { direct_printf_string_payload(b"%s\n", null_args.as_ptr(), 1) }.is_none());
        assert!(unsafe { direct_printf_string_payload(b"[%s]\n", args.as_ptr(), 1) }.is_none());
    }

    #[test]
    fn printf_direct_payload_copy_preserves_snprintf_truncation_boundary() {
        let mut buf = [0u8; 8];
        unsafe {
            copy_direct_printf_payload(buf.as_mut_ptr().cast(), b"abcdef", true, 7);
        }
        assert_eq!(&buf, b"abcdef\n\0");

        let mut truncated = [0u8; 4];
        unsafe {
            copy_direct_printf_payload(truncated.as_mut_ptr().cast(), b"abcdef", true, 3);
        }
        assert_eq!(&truncated, b"abc\0");
    }

    #[test]
    fn printf_direct_unsigned_decimal_preserves_full_length_and_truncation() {
        for (value, expected) in [
            (0u32, "0"),
            (9, "9"),
            (10, "10"),
            (1_000_000, "1000000"),
            (u32::MAX, "4294967295"),
        ] {
            for size in 0..=12 {
                let mut buf = [0x55u8; 12];
                let rc = unsafe {
                    strict_direct_snprintf_u(buf.as_mut_ptr().cast(), size, value as c_uint)
                };
                assert_eq!(rc as usize, expected.len());
                if size > 0 {
                    let copied = expected.len().min(size - 1);
                    assert_eq!(&buf[..copied], &expected.as_bytes()[..copied]);
                    assert_eq!(buf[copied], 0);
                }
            }
        }
    }

    #[test]
    fn printf_direct_newline_stream_only_absorbs_full_buffered_without_flush() {
        let writable = OpenFlags {
            writable: true,
            ..Default::default()
        };
        let full_id = register_stream(StdioStream::with_mode(-1, writable, BufMode::Full));

        assert_eq!(
            unsafe { try_write_direct_s_newline_stream(full_id, b"status=ok") },
            Some(true)
        );
        let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let stream = reg.streams.get(&full_id).expect("registered full stream");
        assert_eq!(stream.pending_flush(), b"status=ok\n");
        assert_eq!(stream.offset(), 10);
        drop(reg);

        let line_id = register_stream(StdioStream::with_mode(-1, writable, BufMode::Line));
        assert_eq!(
            unsafe { try_write_direct_s_newline_stream(line_id, b"status=ok") },
            None
        );
    }
}
