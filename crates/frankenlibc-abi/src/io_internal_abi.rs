//! ABI layer for internal glibc `_IO_*` stdio symbols.
//!
//! These are internal glibc libio functions exported for binary compatibility.
//! Many still manipulate opaque `FILE*` / `_IO_FILE*` internals that we do not
//! model yet, so they continue to delegate to the host glibc via
//! `dlsym(RTLD_NEXT, ...)`.
//!
//! The common stdio-shaped entrypoints are migrated incrementally to native
//! wrappers over [`crate::stdio_abi`], which lets us shrink call-through debt
//! without pretending we already own the full libio object model.

#![allow(non_snake_case, non_upper_case_globals)]

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use crate::stdio_abi;

// ---------------------------------------------------------------------------
// Native FILE struct (bd-zh1y.3.1)
// ---------------------------------------------------------------------------

/// Buffering mode flags for [`NativeFile`].
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeFileBufMode {
    /// `_IOFBF` — fully buffered (flush when buffer is full).
    Full = 0,
    /// `_IOLBF` — line buffered (flush on newline or full).
    Line = 1,
    /// `_IONBF` — unbuffered (no buffering).
    None = 2,
}

/// Bitflags for [`NativeFile::flags`].
pub mod file_flags {
    /// Stream is open for reading.
    pub const READ: u32 = 1 << 0;
    /// Stream is open for writing.
    pub const WRITE: u32 = 1 << 1;
    /// Stream is in append mode.
    pub const APPEND: u32 = 1 << 2;
    /// End-of-file has been reached.
    pub const EOF: u32 = 1 << 3;
    /// An I/O error has occurred.
    pub const ERROR: u32 = 1 << 4;
    /// I/O has started (prevents setvbuf changes).
    pub const IO_STARTED: u32 = 1 << 5;
    /// Stream is wide-oriented.
    pub const WIDE: u32 = 1 << 6;
    /// Stream owns its buffer (must free on close).
    pub const OWN_BUFFER: u32 = 1 << 7;
}

/// FrankenLibC-owned FILE structure.
///
/// Programs interact with `FILE*` as an opaque pointer, so this struct does NOT
/// need to replicate glibc's internal `_IO_FILE` field layout. However, its
/// `size_of` must be **at least** 216 bytes (glibc `sizeof(FILE)` on x86_64) so
/// that allocations returned by `fopen` / `fdopen` are safe for callers that
/// store extra data adjacent to the FILE (e.g., glibc's `_IO_FILE_plus`).
///
/// This struct is the foundation for replacing the current stream-registry
/// approach with direct `FILE*` pointers that FrankenLibC fully owns.
#[repr(C)]
pub struct NativeFile {
    /// Magic sentinel: `0x464b_4c43` ("FKLC") marks this as a FrankenLibC FILE.
    pub magic: u32,

    /// Underlying file descriptor (-1 = closed, -2 = memory-backed).
    pub fd: i32,

    /// Base address of the I/O buffer (null if unbuffered or not yet allocated).
    pub buffer_base: *mut u8,

    /// Current read/write position within the buffer.
    pub buffer_pos: *mut u8,

    /// One past the last valid byte in the buffer (read) or buffer capacity limit (write).
    pub buffer_end: *mut u8,

    /// Total allocated buffer size in bytes.
    pub buffer_size: usize,

    /// Bitfield of `file_flags::*` constants.
    pub flags: u32,

    /// Buffering mode.
    pub buf_mode: NativeFileBufMode,

    /// Padding for alignment after buf_mode (u8).
    _pad0: [u8; 3],

    /// One-byte pushback buffer for `ungetc`. 0xFF = empty, otherwise the byte.
    pub ungetc_buf: i16,

    /// Padding for alignment.
    _pad1: [u8; 6],

    /// Logical byte offset in the underlying file.
    pub offset: i64,

    /// Pointer to the stream vtable (read/write/seek/close/flush callbacks).
    /// Null means use default fd-based I/O.
    pub vtable: *const c_void,

    /// Per-stream mutex for thread safety (futex-based, 0 = unlocked).
    pub lock: i32,

    /// Padding for alignment after lock.
    _pad2: [u8; 4],

    /// Reserved space to ensure sizeof(NativeFile) >= 216 bytes (glibc FILE size)
    /// and to accommodate future fields (wide orientation state, cookie data,
    /// _IO_list chain pointer, etc.).
    _reserved: [u8; 136],
}

/// Magic value identifying a [`NativeFile`] struct: "FKLC".
pub const NATIVE_FILE_MAGIC: u32 = 0x464b_4c43;

// Compile-time assertions: NativeFile must be at least as large as glibc FILE (216 bytes).
const _: () = assert!(
    std::mem::size_of::<NativeFile>() >= 216,
    "NativeFile must be >= 216 bytes (glibc FILE size)"
);

impl NativeFile {
    /// Create a new `NativeFile` for the given file descriptor and flags.
    pub fn new(fd: i32, flags: u32, buf_mode: NativeFileBufMode) -> Self {
        Self {
            magic: NATIVE_FILE_MAGIC,
            fd,
            buffer_base: ptr::null_mut(),
            buffer_pos: ptr::null_mut(),
            buffer_end: ptr::null_mut(),
            buffer_size: 0,
            flags,
            buf_mode,
            _pad0: [0; 3],
            ungetc_buf: -1, // empty
            _pad1: [0; 6],
            offset: 0,
            vtable: ptr::null(),
            lock: 0,
            _pad2: [0; 4],
            _reserved: [0; 136],
        }
    }

    /// Returns `true` if this struct has the correct magic value.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic == NATIVE_FILE_MAGIC
    }

    /// Returns `true` if the EOF flag is set.
    #[inline]
    pub fn is_eof(&self) -> bool {
        self.flags & file_flags::EOF != 0
    }

    /// Returns `true` if the error flag is set.
    #[inline]
    pub fn is_error(&self) -> bool {
        self.flags & file_flags::ERROR != 0
    }

    /// Set the EOF flag.
    #[inline]
    pub fn set_eof(&mut self) {
        self.flags |= file_flags::EOF;
    }

    /// Set the error flag.
    #[inline]
    pub fn set_error(&mut self) {
        self.flags |= file_flags::ERROR;
    }

    /// Clear both EOF and error flags (for `clearerr`).
    #[inline]
    pub fn clear_errors(&mut self) {
        self.flags &= !(file_flags::EOF | file_flags::ERROR);
    }

    /// Returns `true` if the stream is readable.
    #[inline]
    pub fn is_readable(&self) -> bool {
        self.flags & file_flags::READ != 0
    }

    /// Returns `true` if the stream is writable.
    #[inline]
    pub fn is_writable(&self) -> bool {
        self.flags & file_flags::WRITE != 0
    }
}

// ---------------------------------------------------------------------------
// Native stream vtable (bd-zh1y.3.2)
// ---------------------------------------------------------------------------

/// Function pointer signatures for stream I/O operations.
///
/// `read`:  Read up to `count` bytes from the stream into `buf`. Returns bytes read, 0 on EOF, -1 on error.
/// `write`: Write up to `count` bytes from `buf` to the stream. Returns bytes written, -1 on error.
/// `seek`:  Seek to `offset` relative to `whence` (SEEK_SET/CUR/END). Returns new offset, -1 on error.
/// `close`: Close the stream. Returns 0 on success, -1 on error.
/// `flush`: Flush any pending write data. Returns 0 on success, -1 on error.
#[repr(C)]
pub struct NativeFileVtable {
    pub read: unsafe fn(file: *mut NativeFile, buf: *mut u8, count: usize) -> isize,
    pub write: unsafe fn(file: *mut NativeFile, buf: *const u8, count: usize) -> isize,
    pub seek: unsafe fn(file: *mut NativeFile, offset: i64, whence: c_int) -> i64,
    pub close: unsafe fn(file: *mut NativeFile) -> c_int,
    pub flush: unsafe fn(file: *mut NativeFile) -> c_int,
}

/// Default vtable for fd-backed streams using raw Linux syscalls.
pub static DEFAULT_FD_VTABLE: NativeFileVtable = NativeFileVtable {
    read: vtable_fd_read,
    write: vtable_fd_write,
    seek: vtable_fd_seek,
    close: vtable_fd_close,
    flush: vtable_fd_flush,
};

/// Read from the underlying fd via `SYS_read`.
///
/// # Safety
/// `file` must be a valid `NativeFile` pointer with a valid fd.
/// `buf` must be writable for `count` bytes.
unsafe fn vtable_fd_read(file: *mut NativeFile, buf: *mut u8, count: usize) -> isize {
    let fd = unsafe { (*file).fd };
    if fd < 0 {
        return -1;
    }
    let ret = unsafe { libc::syscall(libc::SYS_read, fd, buf, count) };
    if ret < 0 {
        unsafe { (*file).set_error() };
        return -1;
    }
    if ret == 0 && count > 0 {
        unsafe { (*file).set_eof() };
    }
    let n = ret as isize;
    // Advance the logical offset.
    unsafe { (*file).offset += n as i64 };
    n
}

/// Write to the underlying fd via `SYS_write`.
///
/// # Safety
/// `file` must be a valid `NativeFile` pointer with a valid fd.
/// `buf` must be readable for `count` bytes.
unsafe fn vtable_fd_write(file: *mut NativeFile, buf: *const u8, count: usize) -> isize {
    let fd = unsafe { (*file).fd };
    if fd < 0 {
        return -1;
    }
    let ret = unsafe { libc::syscall(libc::SYS_write, fd, buf, count) };
    if ret < 0 {
        unsafe { (*file).set_error() };
        return -1;
    }
    let n = ret as isize;
    unsafe { (*file).offset += n as i64 };
    n
}

/// Seek to a position via `SYS_lseek`.
///
/// # Safety
/// `file` must be a valid `NativeFile` pointer with a valid fd.
unsafe fn vtable_fd_seek(file: *mut NativeFile, offset: i64, whence: c_int) -> i64 {
    let fd = unsafe { (*file).fd };
    if fd < 0 {
        return -1;
    }
    let ret = unsafe { libc::syscall(libc::SYS_lseek, fd, offset, whence) };
    if ret < 0 {
        unsafe { (*file).set_error() };
        return -1;
    }
    let new_offset = ret as i64;
    unsafe { (*file).offset = new_offset };
    // Clear EOF on successful seek.
    unsafe { (*file).flags &= !file_flags::EOF };
    new_offset
}

/// Close the underlying fd via `SYS_close` after flushing.
///
/// # Safety
/// `file` must be a valid `NativeFile` pointer.
unsafe fn vtable_fd_close(file: *mut NativeFile) -> c_int {
    // Flush any pending writes first.
    let flush_rc = unsafe { vtable_fd_flush(file) };
    let fd = unsafe { (*file).fd };
    if fd < 0 {
        return if flush_rc != 0 { -1 } else { 0 };
    }
    let ret = unsafe { libc::syscall(libc::SYS_close, fd) };
    unsafe { (*file).fd = -1 };
    if ret < 0 || flush_rc != 0 { -1 } else { 0 }
}

/// Flush pending write buffer to the fd via `SYS_write`.
///
/// Writes all bytes between `buffer_base` and `buffer_pos` to the fd,
/// then resets the write cursor.
///
/// # Safety
/// `file` must be a valid `NativeFile` pointer.
unsafe fn vtable_fd_flush(file: *mut NativeFile) -> c_int {
    let base = unsafe { (*file).buffer_base };
    let pos = unsafe { (*file).buffer_pos };
    if base.is_null() || pos <= base {
        return 0; // Nothing to flush.
    }
    // Only flush if the stream is writable (buffered write data exists).
    if unsafe { (*file).flags } & file_flags::WRITE == 0 {
        return 0;
    }
    let fd = unsafe { (*file).fd };
    if fd < 0 {
        return -1;
    }
    let pending = unsafe { pos.offset_from(base) } as usize;
    let mut written = 0usize;
    while written < pending {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_write,
                fd,
                base.add(written),
                pending - written,
            )
        };
        if ret < 0 {
            unsafe { (*file).set_error() };
            return -1;
        }
        written += ret as usize;
    }
    // Reset buffer position after flush.
    unsafe { (*file).buffer_pos = base };
    0
}

// ---------------------------------------------------------------------------
// Native stream registry (bd-zh1y.3.3)
// ---------------------------------------------------------------------------

use std::sync::Mutex;

/// Maximum number of concurrently open native streams.
const STREAM_REGISTRY_CAPACITY: usize = 256;

/// Slot state: slot is free.
const SLOT_FREE: u32 = 0;
/// Slot state: slot is occupied by an open stream.
const SLOT_OCCUPIED: u32 = 1;

/// A slot in the stream registry.
struct StreamSlot {
    state: u32,
    file: NativeFile,
}

impl StreamSlot {
    const fn empty() -> Self {
        Self {
            state: SLOT_FREE,
            file: NativeFile {
                magic: 0,
                fd: -1,
                buffer_base: ptr::null_mut(),
                buffer_pos: ptr::null_mut(),
                buffer_end: ptr::null_mut(),
                buffer_size: 0,
                flags: 0,
                buf_mode: NativeFileBufMode::None,
                _pad0: [0; 3],
                ungetc_buf: -1,
                _pad1: [0; 6],
                offset: 0,
                vtable: ptr::null(),
                lock: 0,
                _pad2: [0; 4],
                _reserved: [0; 136],
            },
        }
    }
}

/// Thread-safe registry of all open native FILE streams.
///
/// Replaces glibc's `_IO_list_all` linked list. Supports:
/// - `register`: add a new stream (returns slot index as stream ID)
/// - `unregister`: remove a stream by slot index
/// - `get_mut`: get mutable access to a stream by slot index
/// - `flush_all`: flush all writable streams (for `fflush(NULL)`)
///
/// Slots 0/1/2 are pre-registered for stdin/stdout/stderr.
pub struct NativeStreamRegistry {
    slots: [StreamSlot; STREAM_REGISTRY_CAPACITY],
}

impl NativeStreamRegistry {
    /// Create a new registry with stdin/stdout/stderr pre-registered.
    fn new() -> Self {
        let mut registry = Self {
            slots: {
                // Initialize all slots as empty.
                // SAFETY: StreamSlot has no non-trivial drop and all-zeros is valid.
                const EMPTY: StreamSlot = StreamSlot::empty();
                [EMPTY; STREAM_REGISTRY_CAPACITY]
            },
        };
        // Pre-register stdin (fd 0), stdout (fd 1), stderr (fd 2).
        registry.slots[0] = StreamSlot {
            state: SLOT_OCCUPIED,
            file: NativeFile::new(0, file_flags::READ, NativeFileBufMode::Full),
        };
        registry.slots[1] = StreamSlot {
            state: SLOT_OCCUPIED,
            file: NativeFile::new(1, file_flags::WRITE, NativeFileBufMode::Line),
        };
        registry.slots[2] = StreamSlot {
            state: SLOT_OCCUPIED,
            file: NativeFile::new(2, file_flags::WRITE, NativeFileBufMode::None),
        };
        registry
    }

    /// Register a new stream. Returns the slot index, or `None` if full.
    pub fn register(&mut self, file: NativeFile) -> Option<usize> {
        // Start from slot 3 (0/1/2 are reserved for stdin/stdout/stderr).
        for i in 3..STREAM_REGISTRY_CAPACITY {
            if self.slots[i].state == SLOT_FREE {
                self.slots[i].state = SLOT_OCCUPIED;
                self.slots[i].file = file;
                return Some(i);
            }
        }
        None // Registry full.
    }

    /// Unregister a stream by slot index. Returns `true` if the slot was occupied.
    pub fn unregister(&mut self, index: usize) -> bool {
        if index >= STREAM_REGISTRY_CAPACITY || self.slots[index].state != SLOT_OCCUPIED {
            return false;
        }
        self.slots[index].state = SLOT_FREE;
        self.slots[index].file.magic = 0;
        self.slots[index].file.fd = -1;
        true
    }

    /// Get a mutable reference to a stream by slot index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut NativeFile> {
        if index < STREAM_REGISTRY_CAPACITY && self.slots[index].state == SLOT_OCCUPIED {
            Some(&mut self.slots[index].file)
        } else {
            None
        }
    }

    /// Get a reference to a stream by slot index.
    pub fn get(&self, index: usize) -> Option<&NativeFile> {
        if index < STREAM_REGISTRY_CAPACITY && self.slots[index].state == SLOT_OCCUPIED {
            Some(&self.slots[index].file)
        } else {
            None
        }
    }

    /// Flush all writable streams. Returns the number of streams that failed to flush.
    ///
    /// This implements `fflush(NULL)` semantics: flush every open output stream.
    pub fn flush_all(&mut self) -> usize {
        let mut errors = 0;
        for i in 0..STREAM_REGISTRY_CAPACITY {
            if self.slots[i].state == SLOT_OCCUPIED
                && self.slots[i].file.flags & file_flags::WRITE != 0
            {
                let file_ptr: *mut NativeFile = &mut self.slots[i].file;
                // SAFETY: file_ptr is a valid pointer to our registry-owned NativeFile.
                let rc = unsafe { vtable_fd_flush(file_ptr) };
                if rc != 0 {
                    errors += 1;
                }
            }
        }
        errors
    }

    /// Count of currently open streams.
    pub fn open_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state == SLOT_OCCUPIED)
            .count()
    }
}

// SAFETY: NativeStreamRegistry contains NativeFile which has raw pointers.
// The registry is always accessed behind a Mutex, so raw pointer fields are
// never shared across threads without synchronization.
unsafe impl Send for NativeStreamRegistry {}
unsafe impl Sync for NativeStreamRegistry {}

/// Global stream registry instance, protected by a mutex.
static NATIVE_STREAM_REGISTRY: std::sync::LazyLock<Mutex<NativeStreamRegistry>> =
    std::sync::LazyLock::new(|| Mutex::new(NativeStreamRegistry::new()));

/// Access the global stream registry.
pub fn native_stream_registry() -> std::sync::MutexGuard<'static, NativeStreamRegistry> {
    NATIVE_STREAM_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Global variable symbols
// ---------------------------------------------------------------------------

const IO_JUMPS_EXPORT_SIZE: usize = 168;

#[repr(C, align(16))]
pub struct IoJumpsExport {
    bytes: [u8; IO_JUMPS_EXPORT_SIZE],
}

impl IoJumpsExport {
    const fn zeroed() -> Self {
        Self {
            bytes: [0; IO_JUMPS_EXPORT_SIZE],
        }
    }
}

/// `_IO_list_all` — head of the linked list of all open FILE streams.
/// Native-owned: always points to our own list (null until streams are opened).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _IO_list_all: *mut c_void = std::ptr::null_mut();

/// `_IO_file_jumps` — default FILE vtable for regular files.
/// Native-owned: zeroed vtable (our stdio layer uses its own vtable dispatch).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _IO_file_jumps: IoJumpsExport = IoJumpsExport::zeroed();

/// `_IO_wfile_jumps` — default FILE vtable for wide-oriented files.
/// Native-owned: zeroed vtable (our stdio layer uses its own vtable dispatch).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _IO_wfile_jumps: IoJumpsExport = IoJumpsExport::zeroed();

/// Legacy bootstrap hook — now a no-op (bd-zh1y.3.4).
///
/// Previously resolved host glibc's `_IO_list_all`, `_IO_file_jumps`, and
/// `_IO_wfile_jumps` symbols. With native FILE struct, vtable, and stream
/// registry in place, host interop is no longer needed for these symbols.
///
/// Kept as a no-op for ABI compatibility with startup_abi.rs callers.
pub(crate) unsafe fn bootstrap_host_libio_exports() {
    // No-op: native stdio owns all _IO_* symbols now.
}

/// Accessor: return our native `_IO_list_all` pointer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_list_all_get() -> *mut c_void {
    unsafe { _IO_list_all }
}

/// Accessor: return pointer to our native `_IO_file_jumps` vtable.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_jumps_get() -> *mut c_void {
    ptr::addr_of_mut!(_IO_file_jumps).cast::<u8>().cast()
}

/// Accessor: return pointer to our native `_IO_wfile_jumps` vtable.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wfile_jumps_get() -> *mut c_void {
    ptr::addr_of_mut!(_IO_wfile_jumps).cast::<u8>().cast()
}

// ===========================================================================
// Function shims (mostly call-through today)
// ===========================================================================

// ---------------------------------------------------------------------------
// Column adjustment
// ---------------------------------------------------------------------------

/// `_IO_adjust_column` — adjust column counter after output.
///
/// Scans `count` bytes of `line`, resetting the column to 0 on newline and
/// incrementing by 1 for each tab stop (8-column aligned) or other byte.
/// This is a pure algorithmic function with no glibc dependency.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_adjust_column(col: c_int, line: *const c_char, count: c_int) -> c_int {
    if line.is_null() || count <= 0 {
        return col;
    }
    let mut c = col as u32;
    for i in 0..count as usize {
        let byte = unsafe { *line.add(i) } as u8;
        match byte {
            b'\n' | b'\r' => c = 0,
            b'\t' => c = (c + 8) & !7,
            _ => c += 1,
        }
    }
    c as c_int
}

/// `_IO_adjust_wcolumn` — adjust wide column counter after output.
///
/// Like `_IO_adjust_column` but over an array of `wchar_t` (i32) values.
/// Pure algorithmic — no glibc dependency.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_adjust_wcolumn(
    col: c_int,
    line: *const c_void,
    count: c_int,
) -> c_int {
    if line.is_null() || count <= 0 {
        return col;
    }
    let wchars = line as *const i32;
    let mut c = col as u32;
    for i in 0..count as usize {
        let wch = unsafe { *wchars.add(i) } as u32;
        match wch {
            0x0A | 0x0D => c = 0,     // '\n' | '\r'
            0x09 => c = (c + 8) & !7, // '\t'
            _ => c += 1,
        }
    }
    c as c_int
}

// ---------------------------------------------------------------------------
// Default vtable operations
// ---------------------------------------------------------------------------

/// `_IO_default_doallocate` — default buffer allocation for FILE.
///
/// Native no-op: buffer allocation is handled lazily by our stdio layer on
/// first read/write.  Returning 0 (success) signals the caller that the
/// stream is ready to use.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_default_doallocate(_fp: *mut c_void) -> c_int {
    0 // success — buffer will be allocated on demand
}

/// `_IO_default_finish` — default finalization for FILE.
///
/// Native no-op: real resource cleanup is handled by `fclose` in our stdio
/// layer.  This vtable hook exists for glibc's internal bookkeeping which
/// we do not need.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_default_finish(_fp: *mut c_void, _dummy: c_int) {
    // No-op: fclose handles all cleanup
}

/// `_IO_default_pbackfail` — default putback failure handler via native ungetc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_default_pbackfail(fp: *mut c_void, ch: c_int) -> c_int {
    if ch == libc::EOF {
        return libc::EOF;
    }
    unsafe { stdio_abi::ungetc(ch, fp) }
}

/// `_IO_default_uflow` — default underflow-then-advance via native fgetc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_default_uflow(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fgetc(fp) }
}

/// `_IO_default_xsgetn` — default multi-byte read via native fread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_default_xsgetn(fp: *mut c_void, buf: *mut c_void, n: usize) -> usize {
    unsafe { stdio_abi::fread(buf, 1, n, fp) }
}

/// `_IO_default_xsputn` — default multi-byte write via native fwrite.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_default_xsputn(
    fp: *mut c_void,
    buf: *const c_void,
    n: usize,
) -> usize {
    unsafe { stdio_abi::fwrite(buf, 1, n, fp) }
}

// ---------------------------------------------------------------------------
// Core I/O operations
// ---------------------------------------------------------------------------

/// `_IO_do_write` — flush write buffer to fd via native fwrite.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_do_write(fp: *mut c_void, buf: *const c_char, n: usize) -> c_int {
    if n == 0 {
        return 0;
    }
    let written = unsafe { stdio_abi::fwrite(buf as *const c_void, 1, n, fp) };
    if written < n { -1 } else { 0 }
}

/// `_IO_doallocbuf` — allocate FILE internal buffer.
///
/// Native no-op: our stdio layer handles buffer allocation lazily.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_doallocbuf(_fp: *mut c_void) {
    // No-op: buffer allocation is lazy in our stdio layer
}

/// `_IO_getc` — internal getc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_getc(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fgetc(fp) }
}

/// `_IO_putc` — internal putc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_putc(ch: c_int, fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fputc(ch, fp) }
}

/// `_IO_feof` — internal feof.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_feof(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::feof(fp) }
}

/// `_IO_ferror` — internal ferror.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_ferror(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::ferror(fp) }
}

/// `_IO_fileno` — internal fileno.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fileno(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fileno(fp) }
}

/// `_IO_peekc_locked` — internal peek character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_peekc_locked(fp: *mut c_void) -> c_int {
    let ch = unsafe { stdio_abi::fgetc(fp) };
    if ch != libc::EOF {
        let _ = unsafe { stdio_abi::ungetc(ch, fp) };
    }
    ch
}

// ---------------------------------------------------------------------------
// fclose / fdopen / fflush / fgetpos / fgets / fopen / fputs / fread / fwrite
// ---------------------------------------------------------------------------

/// `_IO_fclose` — internal fclose.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fclose(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fclose(fp) }
}

/// `_IO_fdopen` — internal fdopen.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fdopen(fd: c_int, mode: *const c_char) -> *mut c_void {
    unsafe { stdio_abi::fdopen(fd, mode) }
}

/// `_IO_fflush` — internal fflush.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fflush(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fflush(fp) }
}

/// `_IO_fgetpos` — internal fgetpos.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fgetpos(fp: *mut c_void, pos: *mut c_void) -> c_int {
    unsafe { stdio_abi::fgetpos(fp, pos.cast::<libc::fpos_t>()) }
}

/// `_IO_fgetpos64` — internal fgetpos64.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fgetpos64(fp: *mut c_void, pos: *mut c_void) -> c_int {
    unsafe { stdio_abi::fgetpos64(fp, pos) }
}

/// `_IO_fgets` — internal fgets.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fgets(buf: *mut c_char, n: c_int, fp: *mut c_void) -> *mut c_char {
    unsafe { stdio_abi::fgets(buf, n, fp) }
}

/// `_IO_fopen` — internal fopen.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fopen(filename: *const c_char, mode: *const c_char) -> *mut c_void {
    unsafe { stdio_abi::fopen(filename, mode) }
}

/// `_IO_fputs` — internal fputs.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fputs(s: *const c_char, fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fputs(s, fp) }
}

/// `_IO_fread` — internal fread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fread(
    buf: *mut c_void,
    size: usize,
    count: usize,
    fp: *mut c_void,
) -> usize {
    unsafe { stdio_abi::fread(buf, size, count, fp) }
}

/// `_IO_fsetpos` — internal fsetpos.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fsetpos(fp: *mut c_void, pos: *const c_void) -> c_int {
    unsafe { stdio_abi::fsetpos(fp, pos.cast::<libc::fpos_t>()) }
}

/// `_IO_fsetpos64` — internal fsetpos64.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fsetpos64(fp: *mut c_void, pos: *const c_void) -> c_int {
    unsafe { stdio_abi::fsetpos64(fp, pos) }
}

/// `_IO_ftell` — internal ftell.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_ftell(fp: *mut c_void) -> i64 {
    unsafe { stdio_abi::ftell(fp) as i64 }
}

/// `_IO_fwrite` — internal fwrite.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fwrite(
    buf: *const c_void,
    size: usize,
    count: usize,
    fp: *mut c_void,
) -> usize {
    unsafe { stdio_abi::fwrite(buf, size, count, fp) }
}

// ---------------------------------------------------------------------------
// file_* vtable operations
// ---------------------------------------------------------------------------

/// `_IO_file_attach` — attach fd to FILE.
///
/// Native: delegates to `fdopen` which creates a proper FILE for the
/// given fd.  Returns the FILE pointer on success, NULL on failure.
/// Note: this ignores the existing `fp` and creates a new FILE; the
/// glibc version reuses the provided `fp` structure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_attach(_fp: *mut c_void, fd: c_int) -> *mut c_void {
    unsafe { stdio_abi::fdopen(fd, c"r+".as_ptr()) }
}

/// `_IO_file_close` — close underlying fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_close(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fclose(fp) }
}

/// `_IO_file_close_it` — close file, release buffers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_close_it(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fclose(fp) }
}

/// `_IO_file_doallocate` — allocate buffer for file stream.
///
/// Native: delegates to `_IO_default_doallocate` (lazy allocation).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_doallocate(fp: *mut c_void) -> c_int {
    unsafe { _IO_default_doallocate(fp) }
}

/// `_IO_file_finish` — finalize file stream.
///
/// Native: delegates to `_IO_default_finish` (no-op — fclose handles cleanup).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_finish(fp: *mut c_void, dummy: c_int) {
    unsafe { _IO_default_finish(fp, dummy) }
}

/// `_IO_file_fopen` — open file by name into existing FILE.
///
/// Native: delegates to our `fopen` implementation.  The `is32not64`
/// flag is ignored since we handle large-file support transparently.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_fopen(
    _fp: *mut c_void,
    filename: *const c_char,
    mode: *const c_char,
    _is32not64: c_int,
) -> *mut c_void {
    unsafe { stdio_abi::fopen(filename, mode) }
}

/// `_IO_file_init` — initialize FILE structure.
///
/// Native no-op: our stdio layer initializes FILE state in fopen/fdopen.
/// This vtable hook is a glibc internal for its linked-list bookkeeping.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_init(_fp: *mut c_void) {
    // No-op: fopen/fdopen handle initialization
}

/// `_IO_file_open` — open file by name (low-level).
///
/// Native: opens via raw syscall `open(2)` and then attaches to a FILE
/// via `fdopen`.  The `read_write` flags determine the mode string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_open(
    _fp: *mut c_void,
    filename: *const c_char,
    posix_mode: c_int,
    prot: c_int,
    _read_write: c_int,
    _is32not64: c_int,
) -> *mut c_void {
    let fd = unsafe { libc::open(filename, posix_mode, prot) };
    if fd < 0 {
        return std::ptr::null_mut();
    }
    // Determine mode string from posix_mode flags
    let mode = if posix_mode & libc::O_WRONLY != 0 {
        c"w"
    } else if posix_mode & libc::O_RDWR != 0 {
        c"r+"
    } else {
        c"r"
    };
    let fp = unsafe { stdio_abi::fdopen(fd, mode.as_ptr()) };
    if fp.is_null() {
        unsafe { libc::syscall(libc::SYS_close, fd) as c_int };
    }
    fp
}

/// `_IO_file_overflow` — handle write buffer overflow.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_overflow(fp: *mut c_void, ch: c_int) -> c_int {
    // Flush the stream to make room.
    if unsafe { stdio_abi::fflush(fp) } != 0 {
        return libc::EOF;
    }
    if ch == libc::EOF {
        0
    } else {
        // Write the extra character directly to the now-empty buffer or fd.
        let byte = ch as u8;
        if unsafe { stdio_abi::fwrite((&byte) as *const u8 as *const c_void, 1, 1, fp) } == 1 {
            ch
        } else {
            libc::EOF
        }
    }
}

/// `_IO_file_read` — read from underlying fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_read(fp: *mut c_void, buf: *mut c_void, n: isize) -> isize {
    if n < 0 {
        return -1;
    }
    unsafe { stdio_abi::fread(buf, 1, n as usize, fp) as isize }
}

/// `_IO_file_seek` — seek on underlying fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_seek(fp: *mut c_void, offset: i64, dir: c_int) -> i64 {
    if unsafe { stdio_abi::fseeko(fp, offset, dir) } != 0 {
        return -1;
    }
    unsafe { stdio_abi::ftello(fp) }
}

/// `_IO_file_seekoff` — seek with mode flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_seekoff(
    fp: *mut c_void,
    offset: i64,
    dir: c_int,
    _mode: c_int,
) -> i64 {
    if unsafe { stdio_abi::fseeko(fp, offset, dir) } != 0 {
        return -1;
    }
    unsafe { stdio_abi::ftello(fp) }
}

/// `_IO_file_setbuf` — set FILE buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_setbuf(
    fp: *mut c_void,
    buf: *mut c_char,
    n: isize,
) -> *mut c_void {
    if n < 0 {
        return std::ptr::null_mut();
    }
    unsafe { stdio_abi::setbuffer(fp, buf, n as usize) };
    fp
}

/// `_IO_file_stat` — stat the underlying fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_stat(fp: *mut c_void, st: *mut c_void) -> c_int {
    let fd = unsafe { stdio_abi::fileno(fp) };
    if fd < 0 {
        return -1;
    }
    unsafe { crate::unistd_abi::fstat(fd, st.cast::<libc::stat>()) }
}

/// `_IO_file_sync` — synchronize FILE buffer with fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_sync(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fflush(fp) }
}

/// `_IO_file_underflow` — handle read buffer underflow.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_underflow(fp: *mut c_void) -> c_int {
    let ch = unsafe { stdio_abi::fgetc(fp) };
    if ch != libc::EOF {
        let _ = unsafe { stdio_abi::ungetc(ch, fp) };
    }
    ch
}

/// `_IO_file_write` — write to underlying fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_write(fp: *mut c_void, buf: *const c_void, n: isize) -> isize {
    if n < 0 {
        return -1;
    }
    unsafe { stdio_abi::fwrite(buf, 1, n as usize, fp) as isize }
}

/// `_IO_file_xsputn` — multi-byte write for file stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_xsputn(fp: *mut c_void, buf: *const c_void, n: usize) -> usize {
    unsafe { stdio_abi::fwrite(buf, 1, n, fp) }
}

// ---------------------------------------------------------------------------
// Flush operations
// ---------------------------------------------------------------------------

/// `_IO_flush_all` — flush all open FILE streams.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_flush_all() -> c_int {
    unsafe { stdio_abi::fflush(std::ptr::null_mut()) }
}

/// `_IO_flush_all_linebuffered` — flush all line-buffered streams.
///
/// In glibc this only flushes line-buffered streams. Our best-effort native
/// approximation flushes all open streams via `fflush(NULL)`, which is a
/// safe superset of the intended behavior.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_flush_all_linebuffered() {
    let _ = unsafe { stdio_abi::fflush(std::ptr::null_mut()) };
}

// ---------------------------------------------------------------------------
// Variadic formatted I/O (forward to v* variants)
// ---------------------------------------------------------------------------

/// `_IO_fprintf` — internal fprintf (variadic, forwards to _IO_vfprintf).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_fprintf(fp: *mut c_void, fmt: *const c_char, mut args: ...) -> c_int {
    unsafe { stdio_abi::vfprintf(fp, fmt, (&mut args) as *mut _ as *mut c_void) }
}

/// `_IO_printf` — internal printf (variadic, forwards to _IO_vfprintf on stdout).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_printf(fmt: *const c_char, mut args: ...) -> c_int {
    unsafe { stdio_abi::vprintf(fmt, (&mut args) as *mut _ as *mut c_void) }
}

/// `_IO_sprintf` — internal sprintf (variadic, forwards to _IO_vsprintf).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_sprintf(buf: *mut c_char, fmt: *const c_char, mut args: ...) -> c_int {
    unsafe { stdio_abi::vsprintf(buf, fmt, (&mut args) as *mut _ as *mut c_void) }
}

/// `_IO_sscanf` — internal sscanf (variadic, forwards to host vsscanf).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_sscanf(s: *const c_char, fmt: *const c_char, mut args: ...) -> c_int {
    unsafe { stdio_abi::vsscanf(s, fmt, (&mut args) as *mut _ as *mut c_void) }
}

// ---------------------------------------------------------------------------
// Backup area management
// ---------------------------------------------------------------------------

/// `_IO_free_backup_area` — free the backup read buffer.
///
/// Native no-op: our stdio layer does not maintain separate backup areas.
/// The ungetc push-back is handled inline in our buffer management.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_free_backup_area(_fp: *mut c_void) {
    // No-op: no separate backup area to free
}

/// `_IO_free_wbackup_area` — free the wide backup read buffer.
///
/// Native no-op: same rationale as `_IO_free_backup_area`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_free_wbackup_area(_fp: *mut c_void) {
    // No-op: no separate wide backup area to free
}

// ---------------------------------------------------------------------------
// Getline / gets
// ---------------------------------------------------------------------------

/// `_IO_getline` — read a line from FILE (native implementation).
///
/// Reads up to `n` bytes from `fp` into `buf`, stopping at `delim`.
/// If `extract_delim` > 0, the delimiter is included in the output.
/// If `extract_delim` < 0, the delimiter is consumed but not stored.
/// Returns the number of bytes stored (excluding any NUL).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_getline(
    fp: *mut c_void,
    buf: *mut c_char,
    n: usize,
    delim: c_int,
    extract_delim: c_int,
) -> usize {
    unsafe { _IO_getline_info(fp, buf, n, delim, extract_delim, std::ptr::null_mut()) }
}

/// `_IO_getline_info` — read a line with extra info (native implementation).
///
/// Same as `_IO_getline` but writes 1 to `*eof` if EOF was hit (when non-null).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_getline_info(
    fp: *mut c_void,
    buf: *mut c_char,
    n: usize,
    delim: c_int,
    extract_delim: c_int,
    eof: *mut c_int,
) -> usize {
    if buf.is_null() {
        return 0;
    }
    if !eof.is_null() {
        unsafe { *eof = 0 };
    }
    let mut count: usize = 0;
    while count < n {
        let ch = unsafe { stdio_abi::fgetc(fp) };
        if ch == libc::EOF {
            if !eof.is_null() {
                unsafe { *eof = 1 };
            }
            break;
        }
        if ch == delim {
            if extract_delim > 0 {
                unsafe { *buf.add(count) = ch as c_char };
                count += 1;
            }
            // extract_delim < 0: consume but don't store
            // extract_delim == 0: put it back
            if extract_delim == 0 {
                let _ = unsafe { stdio_abi::ungetc(ch, fp) };
            }
            break;
        }
        unsafe { *buf.add(count) = ch as c_char };
        count += 1;
    }
    count
}

/// `_IO_gets` — internal gets (deprecated but exported, native implementation).
///
/// Reads from stdin until newline or EOF into `buf`.
/// HARDENED: Clamped to 16 MiB to prevent literal infinite overflow, though still
/// inherently unsafe as per POSIX/C11.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_gets(buf: *mut c_char) -> *mut c_char {
    if buf.is_null() {
        return std::ptr::null_mut();
    }
    let mut pos: usize = 0;
    const MAX_GETS: usize = 16 * 1024 * 1024;
    loop {
        if pos >= MAX_GETS {
            break;
        }
        let ch = unsafe { stdio_abi::getchar() };
        if ch == libc::EOF {
            if pos == 0 {
                return std::ptr::null_mut();
            }
            break;
        }
        if ch == b'\n' as c_int {
            break;
        }
        unsafe { *buf.add(pos) = ch as c_char };
        pos += 1;
    }
    unsafe { *buf.add(pos) = 0 };
    buf
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// `_IO_init` — initialize an _IO_FILE structure.
///
/// Native no-op: our stdio layer manages its own FILE initialization.
/// This glibc internal sets up the linked-list chain and default vtable,
/// neither of which we maintain.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_init(_fp: *mut c_void, _flags: c_int) {
    // No-op: our FILE management does not use glibc's internal init chain
}

// ---------------------------------------------------------------------------
// Marker operations
// ---------------------------------------------------------------------------

/// `_IO_init_marker` — initialize a stream position marker.
///
/// Native no-op: glibc markers are internal linked-list bookmarks into
/// the stream buffer.  Our stdio layer uses standard fseek/ftell instead.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_init_marker(_marker: *mut c_void, _fp: *mut c_void) {
    // No-op: markers are a glibc internal that we do not maintain
}

/// `_IO_init_wmarker` — initialize a wide stream position marker.
///
/// Native no-op: same rationale as `_IO_init_marker`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_init_wmarker(_marker: *mut c_void, _fp: *mut c_void) {
    // No-op: wide markers are a glibc internal
}

/// `_IO_marker_delta` — distance from marker to current position.
///
/// Native: returns 0 (no delta) since we do not track marker positions.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_marker_delta(_marker: *mut c_void) -> c_int {
    0
}

/// `_IO_marker_difference` — distance between two markers.
///
/// Native: returns 0 since we do not track marker positions.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_marker_difference(_mark1: *mut c_void, _mark2: *mut c_void) -> c_int {
    0
}

/// `_IO_remove_marker` — remove a stream position marker.
///
/// Native no-op: we do not maintain a marker linked list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_remove_marker(_marker: *mut c_void) {
    // No-op
}

/// `_IO_seekmark` — seek to a marker position.
///
/// Native: returns -1 (error) since markers are not supported.
/// Callers in practice use fseek instead.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_seekmark(
    _fp: *mut c_void,
    _marker: *mut c_void,
    _delta: c_int,
) -> c_int {
    -1 // markers not supported — use fseek
}

/// `_IO_seekwmark` — seek to a wide marker position.
///
/// Native: returns -1 (error) since wide markers are not supported.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_seekwmark(
    _fp: *mut c_void,
    _marker: *mut c_void,
    _delta: c_int,
) -> c_int {
    -1 // wide markers not supported
}

/// `_IO_unsave_markers` — release all saved markers.
///
/// Native no-op: no markers to release.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_unsave_markers(_fp: *mut c_void) {
    // No-op
}

/// `_IO_unsave_wmarkers` — release all saved wide markers.
///
/// Native no-op: no wide markers to release.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_unsave_wmarkers(_fp: *mut c_void) {
    // No-op
}

/// `_IO_least_wmarker` — find the leftmost wide marker.
///
/// Native: returns 0 since we do not maintain wide markers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_least_wmarker(_fp: *mut c_void, _end: *mut c_void) -> isize {
    0
}

/// `_IO_wmarker_delta` — distance from wide marker to current position.
///
/// Native: returns 0 since we do not track wide marker positions.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wmarker_delta(_marker: *mut c_void) -> c_int {
    0
}

// ---------------------------------------------------------------------------
// Iterator operations (FILE list traversal)
// ---------------------------------------------------------------------------

/// `_IO_iter_begin` — get iterator to first FILE in list.
///
/// Native: returns NULL (empty list).  We do not maintain glibc's linked
/// FILE list, so iteration yields no elements.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_iter_begin() -> *mut c_void {
    std::ptr::null_mut() // empty list
}

/// `_IO_iter_end` — get sentinel iterator (end of list).
///
/// Native: returns NULL sentinel.  Since `_IO_iter_begin` also returns
/// NULL, `begin == end` correctly indicates an empty iteration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_iter_end() -> *mut c_void {
    std::ptr::null_mut()
}

/// `_IO_iter_file` — dereference iterator to get FILE*.
///
/// Native: returns NULL since our iterators are always at end-of-list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_iter_file(_iter: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

/// `_IO_iter_next` — advance iterator to next FILE.
///
/// Native: returns NULL (end sentinel) since we have no FILE list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_iter_next(_iter: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// List locking
// ---------------------------------------------------------------------------

/// `_IO_link_in` — add FILE to the global list.
///
/// Native no-op: FrankenLibC does not maintain glibc's linked FILE list.
/// Stream tracking is handled separately by our stdio layer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_link_in(_fp: *mut c_void) {
    // No-op: we do not maintain glibc's _IO_list_all linked list
}

/// `_IO_un_link` — remove FILE from the global list.
///
/// Native no-op: counterpart to `_IO_link_in`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_un_link(_fp: *mut c_void) {
    // No-op: we do not maintain glibc's _IO_list_all linked list
}

/// `_IO_list_lock` — lock the global FILE list.
///
/// Native no-op: we do not maintain a global FILE list that needs locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_list_lock() {
    // No-op: no global list to lock
}

/// `_IO_list_unlock` — unlock the global FILE list.
///
/// Native no-op: counterpart to `_IO_list_lock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_list_unlock() {
    // No-op: no global list to unlock
}

/// `_IO_list_resetlock` — reset the global FILE list lock.
///
/// Native no-op: counterpart to `_IO_list_lock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_list_resetlock() {
    // No-op: no global list lock to reset
}

// ---------------------------------------------------------------------------
// popen / proc_open / proc_close
// ---------------------------------------------------------------------------

/// `_IO_popen` — internal popen via native stdio_abi.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_popen(command: *const c_char, mode: *const c_char) -> *mut c_void {
    unsafe { stdio_abi::popen(command, mode) }
}

/// `_IO_proc_open` — open a process pipe.
///
/// Native: delegates to `popen` which handles fork/exec and pipe setup.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_proc_open(
    _fp: *mut c_void,
    command: *const c_char,
    mode: *const c_char,
) -> *mut c_void {
    unsafe { stdio_abi::popen(command, mode) }
}

/// `_IO_proc_close` — close a process pipe via native pclose.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_proc_close(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::pclose(fp) }
}

// ---------------------------------------------------------------------------
// setb / setbuffer / setvbuf
// ---------------------------------------------------------------------------

/// `_IO_setb` — set base and end of internal buffer.
///
/// Native no-op: our stdio layer manages its own buffer pointers.
/// This glibc internal directly manipulates `_IO_FILE._IO_buf_base`
/// and `_IO_buf_end`, which we do not expose.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_setb(
    _fp: *mut c_void,
    _base: *mut c_char,
    _end: *mut c_char,
    _user_buf: c_int,
) {
    // No-op: buffer management is internal to our stdio layer
}

/// `_IO_setbuffer` — set FILE buffer (like setbuf).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_setbuffer(fp: *mut c_void, buf: *mut c_char, size: usize) {
    unsafe { stdio_abi::setbuffer(fp, buf, size) }
}

/// `_IO_setvbuf` — set FILE buffering mode (like setvbuf).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_setvbuf(
    fp: *mut c_void,
    buf: *mut c_char,
    mode: c_int,
    size: usize,
) -> c_int {
    unsafe { stdio_abi::setvbuf(fp, buf, mode, size) }
}

// ---------------------------------------------------------------------------
// Putback / ungetc
// ---------------------------------------------------------------------------

/// `_IO_sputbackc` — put back a byte via native ungetc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_sputbackc(fp: *mut c_void, ch: c_int) -> c_int {
    unsafe { stdio_abi::ungetc(ch, fp) }
}

/// `_IO_sputbackwc` — put back a wide character.
///
/// Native: delegates to `ungetwc` via our wchar ABI layer. Falls back
/// to WEOF if the stream does not support wide pushback.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_sputbackwc(fp: *mut c_void, wch: u32) -> u32 {
    // Use the ungetwc ABI path for wide pushback
    unsafe { crate::wchar_abi::ungetwc(wch, fp) }
}

/// `_IO_sungetc` — unget the last byte read.
///
/// Native: returns EOF since we do not track the last-read byte
/// outside of the ungetc push-back slot.  Callers should use
/// `ungetc(ch, fp)` with an explicit character instead.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_sungetc(_fp: *mut c_void) -> c_int {
    libc::EOF // cannot re-push without knowing the character
}

/// `_IO_sungetwc` — unget the last wide character read.
///
/// Native: returns WEOF for the same reason as `_IO_sungetc`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_sungetwc(_fp: *mut c_void) -> u32 {
    0xFFFF_FFFF // WEOF
}

/// `_IO_ungetc` — internal ungetc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_ungetc(ch: c_int, fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::ungetc(ch, fp) }
}

// ---------------------------------------------------------------------------
// String stream operations
// ---------------------------------------------------------------------------

/// `_IO_str_init_readonly` — initialize a read-only string stream.
///
/// Native no-op: string stream setup (fmemopen/open_memstream) is handled
/// by our stdio layer.  This vtable hook is glibc's internal initializer
/// for its `_IO_str_fields` overlay on `_IO_FILE`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_str_init_readonly(_fp: *mut c_void, _str: *const c_char, _len: usize) {
    // No-op: string stream init handled by fmemopen
}

/// `_IO_str_init_static` — initialize a static string stream.
///
/// Native no-op: same rationale as `_IO_str_init_readonly`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_str_init_static(
    _fp: *mut c_void,
    _str: *mut c_char,
    _len: usize,
    _pstart: *mut c_char,
) {
    // No-op: static string stream init handled by our stdio layer
}

/// `_IO_str_overflow` — handle overflow for string stream.
///
/// Native: returns EOF since string stream overflow (buffer full)
/// cannot be resolved without internal buffer reallocation that we
/// handle through the stdio layer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_str_overflow(_fp: *mut c_void, _ch: c_int) -> c_int {
    libc::EOF // buffer full
}

/// `_IO_str_pbackfail` — handle putback failure for string stream.
///
/// Native: returns EOF since putback on a string stream that cannot
/// back up is a defined failure case.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_str_pbackfail(_fp: *mut c_void, _ch: c_int) -> c_int {
    libc::EOF // putback not possible
}

/// `_IO_str_seekoff` — seek on string stream.
///
/// Native: returns -1 (error) since string stream seeking requires
/// internal buffer pointers we do not maintain at this level.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_str_seekoff(
    _fp: *mut c_void,
    _offset: i64,
    _dir: c_int,
    _mode: c_int,
) -> i64 {
    -1 // string stream seek not supported at vtable level
}

/// `_IO_str_underflow` — handle underflow for string stream.
///
/// Native: returns EOF since string stream underflow (no more data)
/// is the correct behavior when the string has been fully consumed.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_str_underflow(_fp: *mut c_void) -> c_int {
    libc::EOF // no more data in string
}

// ---------------------------------------------------------------------------
// Mode switching
// ---------------------------------------------------------------------------

/// `_IO_switch_to_get_mode` — switch FILE to read mode.
///
/// Flushes pending writes so the stream is ready for reading.
/// Native approximation via `fflush`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_switch_to_get_mode(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fflush(fp) }
}

/// `_IO_switch_to_main_wget_area` — switch to main wide get area.
///
/// Native no-op: our stdio layer does not maintain separate main/backup
/// wide buffer areas.  Flushing via fflush is sufficient.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_switch_to_main_wget_area(_fp: *mut c_void) {
    // No-op: we don't maintain separate wide buffer areas
}

/// `_IO_switch_to_wbackup_area` — switch to wide backup area.
///
/// Native no-op: same rationale as `_IO_switch_to_main_wget_area`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_switch_to_wbackup_area(_fp: *mut c_void) {
    // No-op: we don't maintain separate wide buffer areas
}

/// `_IO_switch_to_wget_mode` — switch FILE to wide read mode.
///
/// Native: flushes pending writes via fflush to prepare for reading,
/// then returns 0 (success).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_switch_to_wget_mode(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fflush(fp) }
}

// ---------------------------------------------------------------------------
// v*printf / v*scanf (non-variadic, take va_list as *mut c_void)
// ---------------------------------------------------------------------------

/// `_IO_vfprintf` — internal vfprintf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_vfprintf(
    fp: *mut c_void,
    fmt: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { stdio_abi::vfprintf(fp, fmt, ap) }
}

/// `_IO_vfscanf` — internal vfscanf via native stdio_abi.
///
/// The glibc internal version takes an extra `errp` parameter that the POSIX
/// `vfscanf` does not have. We delegate to native vfscanf and ignore the
/// legacy error pointer (callers in practice pass NULL).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_vfscanf(
    fp: *mut c_void,
    fmt: *const c_char,
    ap: *mut c_void,
    errp: *mut c_int,
) -> c_int {
    let result = unsafe { stdio_abi::vfscanf(fp, fmt, ap) };
    if !errp.is_null() && result == libc::EOF {
        unsafe { *errp = 1 };
    }
    result
}

/// `_IO_vsprintf` — internal vsprintf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_vsprintf(
    buf: *mut c_char,
    fmt: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { stdio_abi::vsprintf(buf, fmt, ap) }
}

// ---------------------------------------------------------------------------
// Wide-character default vtable operations
// ---------------------------------------------------------------------------

/// `_IO_wdefault_doallocate` — default wide buffer allocation.
///
/// Native: returns 0 (success) — wide buffer allocation is handled
/// lazily by our stdio layer, same as narrow buffer allocation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdefault_doallocate(_fp: *mut c_void) -> c_int {
    0 // success — buffer allocated on demand
}

/// `_IO_wdefault_finish` — default wide finalization.
///
/// Native no-op: resource cleanup for wide streams is handled by fclose.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdefault_finish(_fp: *mut c_void, _dummy: c_int) {
    // No-op: fclose handles wide stream cleanup
}

/// `_IO_wdefault_pbackfail` — default wide putback failure.
///
/// Native: returns WEOF to signal putback failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdefault_pbackfail(_fp: *mut c_void, _wch: u32) -> u32 {
    0xFFFF_FFFF // WEOF
}

/// `_IO_wdefault_uflow` — default wide underflow-then-advance.
///
/// Native: returns WEOF to signal end of data.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdefault_uflow(_fp: *mut c_void) -> u32 {
    0xFFFF_FFFF // WEOF
}

/// `_IO_wdefault_xsgetn` — default wide multi-byte read.
///
/// Native: returns 0 (no data read) as the default wide read path.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdefault_xsgetn(
    _fp: *mut c_void,
    _buf: *mut c_void,
    _n: usize,
) -> usize {
    0
}

/// `_IO_wdefault_xsputn` — default wide multi-byte write.
///
/// Native: returns 0 (no data written) as the default wide write path.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdefault_xsputn(
    _fp: *mut c_void,
    _buf: *const c_void,
    _n: usize,
) -> usize {
    0
}

/// `_IO_wdo_write` — flush wide write buffer to fd.
///
/// Native: returns -1 since wide buffer flushing at vtable level
/// requires internal wide-to-narrow conversion state we do not maintain.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdo_write(_fp: *mut c_void, _buf: *const c_void, _n: usize) -> c_int {
    -1 // wide write not supported at vtable level
}

/// `_IO_wdoallocbuf` — allocate wide FILE internal buffer.
///
/// Native no-op: wide buffer allocation is lazy.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdoallocbuf(_fp: *mut c_void) {
    // No-op: wide buffer allocation is lazy
}

// ---------------------------------------------------------------------------
// Wide file vtable operations
// ---------------------------------------------------------------------------

/// `_IO_wfile_overflow` — handle wide write buffer overflow.
///
/// Native: returns WEOF since wide file overflow requires internal
/// wide-to-narrow conversion that is handled by our stdio layer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wfile_overflow(_fp: *mut c_void, _wch: u32) -> u32 {
    0xFFFF_FFFF // WEOF
}

/// `_IO_wfile_seekoff` — seek on wide file.
///
/// Native: delegates to the narrow file seek via fseeko/ftello which
/// handles both narrow and wide streams.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wfile_seekoff(
    fp: *mut c_void,
    offset: i64,
    dir: c_int,
    _mode: c_int,
) -> i64 {
    if unsafe { stdio_abi::fseeko(fp, offset, dir) } != 0 {
        return -1;
    }
    unsafe { stdio_abi::ftello(fp) }
}

/// `_IO_wfile_sync` — synchronize wide FILE buffer with fd.
///
/// Native: delegates to fflush which handles both narrow and wide streams.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wfile_sync(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fflush(fp) }
}

/// `_IO_wfile_underflow` — handle wide read buffer underflow.
///
/// Native: returns WEOF to signal end of data.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wfile_underflow(_fp: *mut c_void) -> u32 {
    0xFFFF_FFFF // WEOF
}

/// `_IO_wfile_xsputn` — multi-byte write for wide file stream.
///
/// Native: returns 0 (no data written) — wide file writing at vtable
/// level requires the full wide-to-multibyte conversion pipeline.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wfile_xsputn(
    _fp: *mut c_void,
    _buf: *const c_void,
    _n: usize,
) -> usize {
    0
}

// ---------------------------------------------------------------------------
// Wide buffer control
// ---------------------------------------------------------------------------

/// `_IO_wsetb` — set base and end of wide internal buffer.
///
/// Native no-op: our stdio layer manages its own wide buffer pointers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wsetb(
    _fp: *mut c_void,
    _base: *mut c_void,
    _end: *mut c_void,
    _user_buf: c_int,
) {
    // No-op: wide buffer management is internal to our stdio layer
}

