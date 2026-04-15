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

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicI8, Ordering};

use crate::runtime_policy;
use crate::stdio_abi;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};
use parking_lot::ReentrantMutex;

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

const GLIBC_IO_MAGIC: i32 = 0xFBAD_0000u32 as i32;
const GLIBC_IO_EOF_SEEN: i32 = 0x0010;
const GLIBC_IO_ERR_SEEN: i32 = 0x0020;
const GLIBC_234_IO_FILE_SIZE: usize = 216;
const GLIBC_234_IO_FILE_PLUS_VTABLE_OFFSET: usize = GLIBC_234_IO_FILE_SIZE;
const IO_JUMPS_EXPORT_SIZE: usize = 168;

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

#[allow(non_camel_case_types)]
#[repr(C)]
struct _IO_FILE_Layout {
    _flags: c_int,
    _padding0: c_int,
    _IO_read_ptr: *mut c_char,
    _IO_read_end: *mut c_char,
    _IO_read_base: *mut c_char,
    _IO_write_base: *mut c_char,
    _IO_write_ptr: *mut c_char,
    _IO_write_end: *mut c_char,
    _IO_buf_base: *mut c_char,
    _IO_buf_end: *mut c_char,
    _IO_save_base: *mut c_char,
    _IO_backup_base: *mut c_char,
    _IO_save_end: *mut c_char,
    _markers: *mut c_void,
    _chain: *mut _IO_FILE_Layout,
    _fileno: c_int,
    _flags2: c_int,
    _old_offset: libc::off_t,
    _cur_column: u16,
    _vtable_offset: i8,
    _shortbuf: [c_char; 1],
    _padding1: [u8; 4],
    _lock: *mut c_void,
    _offset: libc::off64_t,
    _codecvt: *mut c_void,
    _wide_data: *mut c_void,
    _freeres_list: *mut _IO_FILE_Layout,
    _freeres_buf: *mut c_void,
    _pad5: usize,
    _mode: c_int,
    _unused2: [u8; 20],
}

impl _IO_FILE_Layout {
    fn new(fd: c_int) -> Self {
        Self {
            _flags: GLIBC_IO_MAGIC,
            _padding0: 0,
            _IO_read_ptr: ptr::null_mut(),
            _IO_read_end: ptr::null_mut(),
            _IO_read_base: ptr::null_mut(),
            _IO_write_base: ptr::null_mut(),
            _IO_write_ptr: ptr::null_mut(),
            _IO_write_end: ptr::null_mut(),
            _IO_buf_base: ptr::null_mut(),
            _IO_buf_end: ptr::null_mut(),
            _IO_save_base: ptr::null_mut(),
            _IO_backup_base: ptr::null_mut(),
            _IO_save_end: ptr::null_mut(),
            _markers: ptr::null_mut(),
            _chain: ptr::null_mut(),
            _fileno: fd,
            _flags2: 0,
            _old_offset: 0,
            _cur_column: 0,
            _vtable_offset: 0,
            _shortbuf: [0],
            _padding1: [0; 4],
            _lock: ptr::null_mut(),
            _offset: 0,
            _codecvt: ptr::null_mut(),
            _wide_data: ptr::null_mut(),
            _freeres_list: ptr::null_mut(),
            _freeres_buf: ptr::null_mut(),
            _pad5: 0,
            _mode: 0,
            _unused2: [0; 20],
        }
    }
}

// ---------------------------------------------------------------------------
// _IO_jump_t vtable (bd-9chy.15)
// ---------------------------------------------------------------------------

/// Function pointer types for glibc `_IO_jump_t` vtable slots.
///
/// These match the signatures in glibc's `libio/libioP.h`. The `fp` parameter
/// is always `*mut c_void` (really `*mut _IO_FILE`) to maintain ABI compat.
#[allow(non_camel_case_types)]
pub mod io_jump_fns {
    use std::ffi::{c_int, c_void};

    /// `__finish`: finalize stream (called by fclose after flush).
    pub type finish_t = unsafe extern "C" fn(fp: *mut c_void, dummy: c_int);
    /// `__overflow`: handle write buffer full / put single char.
    pub type overflow_t = unsafe extern "C" fn(fp: *mut c_void, ch: c_int) -> c_int;
    /// `__underflow`: refill read buffer, don't advance (peek).
    pub type underflow_t = unsafe extern "C" fn(fp: *mut c_void) -> c_int;
    /// `__uflow`: refill read buffer and return next char (advance).
    pub type uflow_t = unsafe extern "C" fn(fp: *mut c_void) -> c_int;
    /// `__pbackfail`: push back a character when buffer full.
    pub type pbackfail_t = unsafe extern "C" fn(fp: *mut c_void, ch: c_int) -> c_int;
    /// `__xsputn`: write multiple bytes.
    pub type xsputn_t =
        unsafe extern "C" fn(fp: *mut c_void, buf: *const c_void, n: usize) -> usize;
    /// `__xsgetn`: read multiple bytes.
    pub type xsgetn_t = unsafe extern "C" fn(fp: *mut c_void, buf: *mut c_void, n: usize) -> usize;
    /// `__seekoff`: seek relative to whence.
    pub type seekoff_t =
        unsafe extern "C" fn(fp: *mut c_void, offset: i64, dir: c_int, mode: c_int) -> i64;
    /// `__seekpos`: seek to absolute position.
    pub type seekpos_t = unsafe extern "C" fn(fp: *mut c_void, pos: i64, mode: c_int) -> i64;
    /// `__setbuf`: set stream buffer.
    pub type setbuf_t =
        unsafe extern "C" fn(fp: *mut c_void, buf: *mut c_void, size: isize) -> *mut c_void;
    /// `__sync`: synchronize buffer with underlying fd.
    pub type sync_t = unsafe extern "C" fn(fp: *mut c_void) -> c_int;
    /// `__doallocate`: allocate internal buffer.
    pub type doallocate_t = unsafe extern "C" fn(fp: *mut c_void) -> c_int;
    /// `__read`: low-level read from fd.
    pub type read_t = unsafe extern "C" fn(fp: *mut c_void, buf: *mut c_void, n: isize) -> isize;
    /// `__write`: low-level write to fd.
    pub type write_t = unsafe extern "C" fn(fp: *mut c_void, buf: *const c_void, n: isize) -> isize;
    /// `__seek`: low-level lseek on fd.
    pub type seek_t = unsafe extern "C" fn(fp: *mut c_void, offset: i64, dir: c_int) -> i64;
    /// `__close`: close underlying fd.
    pub type close_t = unsafe extern "C" fn(fp: *mut c_void) -> c_int;
    /// `__stat`: fstat underlying fd.
    pub type stat_t = unsafe extern "C" fn(fp: *mut c_void, st: *mut c_void) -> c_int;
    /// `__showmanyc`: return lower bound of available chars (rarely used).
    pub type showmanyc_t = unsafe extern "C" fn(fp: *mut c_void) -> c_int;
    /// `__imbue`: set locale for stream (rarely used).
    pub type imbue_t = unsafe extern "C" fn(fp: *mut c_void, locale: *mut c_void);
}

/// glibc `_IO_jump_t` vtable structure with 21 function pointer slots.
///
/// Layout matches glibc 2.34 x86_64. Total size: 168 bytes (21 × 8).
/// The first two slots (`__dummy`, `__dummy2`) are size_t values used by
/// glibc for vtable validation; we set them to magic values.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct _IO_jump_t {
    /// Magic marker for vtable validation (glibc sets this to 0).
    pub __dummy: usize,
    /// Second magic marker.
    pub __dummy2: usize,
    /// Finalize stream.
    pub __finish: io_jump_fns::finish_t,
    /// Handle write buffer overflow.
    pub __overflow: io_jump_fns::overflow_t,
    /// Peek at next input char (refill buffer, don't advance).
    pub __underflow: io_jump_fns::underflow_t,
    /// Get next input char (refill buffer, advance).
    pub __uflow: io_jump_fns::uflow_t,
    /// Push back a character.
    pub __pbackfail: io_jump_fns::pbackfail_t,
    /// Write multiple bytes.
    pub __xsputn: io_jump_fns::xsputn_t,
    /// Read multiple bytes.
    pub __xsgetn: io_jump_fns::xsgetn_t,
    /// Seek relative to whence.
    pub __seekoff: io_jump_fns::seekoff_t,
    /// Seek to absolute position.
    pub __seekpos: io_jump_fns::seekpos_t,
    /// Set stream buffer.
    pub __setbuf: io_jump_fns::setbuf_t,
    /// Synchronize buffer with fd.
    pub __sync: io_jump_fns::sync_t,
    /// Allocate internal buffer.
    pub __doallocate: io_jump_fns::doallocate_t,
    /// Low-level read.
    pub __read: io_jump_fns::read_t,
    /// Low-level write.
    pub __write: io_jump_fns::write_t,
    /// Low-level seek.
    pub __seek: io_jump_fns::seek_t,
    /// Close fd.
    pub __close: io_jump_fns::close_t,
    /// Stat fd.
    pub __stat: io_jump_fns::stat_t,
    /// Return available chars (rarely used).
    pub __showmanyc: io_jump_fns::showmanyc_t,
    /// Set locale (rarely used).
    pub __imbue: io_jump_fns::imbue_t,
}

// Compile-time assertion: _IO_jump_t must be exactly 168 bytes.
const _: () = assert!(
    std::mem::size_of::<_IO_jump_t>() == IO_JUMPS_EXPORT_SIZE,
    "_IO_jump_t must be exactly 168 bytes (21 slots × 8 bytes)"
);

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn io_file_layout_matches_glibc_234_x86_64_offsets() {
        assert_eq!(
            std::mem::size_of::<_IO_FILE_Layout>(),
            GLIBC_234_IO_FILE_SIZE
        );
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _flags), 0);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _IO_read_ptr), 8);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _IO_read_end), 16);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _IO_read_base), 24);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _IO_write_base), 32);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _IO_write_ptr), 40);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _IO_write_end), 48);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _IO_buf_base), 56);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _IO_buf_end), 64);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _IO_save_base), 72);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _IO_backup_base), 80);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _IO_save_end), 88);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _markers), 96);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _chain), 104);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _fileno), 112);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _flags2), 116);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _old_offset), 120);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _cur_column), 128);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _vtable_offset), 130);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _shortbuf), 131);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _lock), 136);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _offset), 144);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _codecvt), 152);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _wide_data), 160);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _freeres_list), 168);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _freeres_buf), 176);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _pad5), 184);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _mode), 192);
        assert_eq!(std::mem::offset_of!(_IO_FILE_Layout, _unused2), 196);
    }

    #[test]
    fn native_file_is_a_real_io_file_plus_shape() {
        assert_eq!(
            std::mem::offset_of!(NativeFile, vtable),
            GLIBC_234_IO_FILE_PLUS_VTABLE_OFFSET
        );
        assert!(
            std::mem::size_of::<NativeFile>() > std::mem::size_of::<_IO_FILE_Layout>(),
            "NativeFile must carry private state beyond the glibc _IO_FILE prefix"
        );
        assert!(
            std::mem::size_of::<NativeFile>() <= 4096,
            "NativeFile must remain slab-friendly"
        );
    }

    #[test]
    fn io_jump_t_layout_is_correct() {
        // _IO_jump_t must be exactly 168 bytes (21 slots × 8 bytes).
        assert_eq!(std::mem::size_of::<_IO_jump_t>(), 168);

        // Verify offsets of key slots (8-byte alignment).
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __dummy), 0);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __dummy2), 8);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __finish), 16);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __overflow), 24);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __underflow), 32);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __uflow), 40);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __pbackfail), 48);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __xsputn), 56);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __xsgetn), 64);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __seekoff), 72);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __seekpos), 80);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __setbuf), 88);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __sync), 96);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __doallocate), 104);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __read), 112);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __write), 120);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __seek), 128);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __close), 136);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __stat), 144);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __showmanyc), 152);
        assert_eq!(std::mem::offset_of!(_IO_jump_t, __imbue), 160);
    }

    #[test]
    fn native_io_jump_t_is_initialized() {
        // Verify that NATIVE_IO_JUMP_T has non-null function pointers.
        assert!(NATIVE_IO_JUMP_T.__finish as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__overflow as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__underflow as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__uflow as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__pbackfail as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__xsputn as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__xsgetn as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__seekoff as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__seekpos as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__setbuf as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__sync as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__doallocate as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__read as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__write as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__seek as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__close as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__stat as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__showmanyc as usize != 0);
        assert!(NATIVE_IO_JUMP_T.__imbue as usize != 0);
    }

    #[test]
    fn native_file_has_vtable_set() {
        // Creating a NativeFile should automatically set the vtable.
        let file = NativeFile::new(42, file_flags::READ, NativeFileBufMode::Full);
        assert!(!file.vtable.is_null());
        // The vtable should point to NATIVE_IO_JUMP_T.
        assert_eq!(
            file.vtable as *const _IO_jump_t,
            ptr::addr_of!(NATIVE_IO_JUMP_T)
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeFileRuntimeMathHooks {
    last_policy_id: u32,
    last_action: u32,
    last_latency_ns: u64,
    last_sequence: u64,
}

impl NativeFileRuntimeMathHooks {
    const fn new() -> Self {
        Self {
            last_policy_id: 0,
            last_action: 0,
            last_latency_ns: 0,
            last_sequence: 0,
        }
    }
}

/// Backing storage type for NativeFile streams.
///
/// Distinguishes between file-descriptor-backed streams (normal files/pipes)
/// and memory-backed streams (fmemopen, open_memstream).
#[derive(Debug)]
#[allow(dead_code)] // Memory stream variants are WIP - used when native fmemopen is wired
pub(crate) enum NativeFileBacking {
    /// File descriptor backed stream (fopen, fdopen, popen).
    Fd(c_int),
    /// Fixed-size memory buffer (fmemopen with caller buffer or internal allocation).
    /// - `buf`: pointer to the memory buffer
    /// - `size`: total buffer size
    /// - `content_len`: current content length for append positioning
    /// - `owns`: true if we allocated the buffer and must free it on close
    MemoryFixed {
        buf: *mut u8,
        size: usize,
        content_len: usize,
        owns: bool,
    },
    /// Growing memory buffer (open_memstream, open_wmemstream).
    /// - `buf_ptr`: caller's buffer pointer location (we write the current buffer here)
    /// - `size_ptr`: caller's size location (we write the current size here)
    /// - `capacity`: current allocated capacity
    /// - `data`: our owned growing buffer
    MemoryGrowing {
        buf_ptr: *mut *mut c_char,
        size_ptr: *mut usize,
        capacity: usize,
        data: Vec<u8>,
    },
}

// SAFETY: The raw pointers in NativeFileBacking are only accessed while
// holding the NativeFile's ReentrantMutex lock, and the memory they point
// to must remain valid for the stream's lifetime per POSIX contract.
unsafe impl Send for NativeFileBacking {}

#[derive(Debug)]
struct NativeFileLocked {
    magic: u32,
    #[allow(dead_code)] // WIP: used when native fmemopen is wired
    backing: NativeFileBacking,
    buffer_base: *mut u8,
    buffer_pos: *mut u8,
    buffer_end: *mut u8,
    buffer_capacity: usize,
    buf_mode: NativeFileBufMode,
    eof: bool,
    error: bool,
    ungetc: Option<u8>,
    generation: u64,
    healing_budget: u32,
    _mbstate: libc::mbstate_t,
    open_flags: u32,
    fingerprint: [u8; 16],
    runtime_math_hooks: NativeFileRuntimeMathHooks,
    /// Child PID for streams opened via popen. Set to Some(pid) during popen,
    /// read and cleared by pclose to waitpid on the child.
    popen_child_pid: Option<i32>,
}

impl NativeFileLocked {
    fn new(fd: c_int, open_flags: u32, buf_mode: NativeFileBufMode) -> Self {
        Self::new_with_backing(NativeFileBacking::Fd(fd), open_flags, buf_mode)
    }

    fn new_with_backing(
        backing: NativeFileBacking,
        open_flags: u32,
        buf_mode: NativeFileBufMode,
    ) -> Self {
        // Compute fd for fingerprint (use -1 for memory streams)
        let fd = match &backing {
            NativeFileBacking::Fd(fd) => *fd,
            NativeFileBacking::MemoryFixed { .. } | NativeFileBacking::MemoryGrowing { .. } => -1,
        };
        let mut fingerprint = [0u8; 16];
        fingerprint[..4].copy_from_slice(&NATIVE_FILE_MAGIC.to_le_bytes());
        fingerprint[4..8].copy_from_slice(&fd.to_le_bytes());
        fingerprint[8..12].copy_from_slice(&open_flags.to_le_bytes());
        fingerprint[12..16].copy_from_slice(&(NATIVE_FILE_MAGIC ^ open_flags).to_le_bytes());

        Self {
            magic: NATIVE_FILE_MAGIC,
            backing,
            buffer_base: ptr::null_mut(),
            buffer_pos: ptr::null_mut(),
            buffer_end: ptr::null_mut(),
            buffer_capacity: 0,
            buf_mode,
            eof: false,
            error: false,
            ungetc: None,
            generation: 0,
            healing_budget: 0,
            // SAFETY: glibc's mbstate_t is a plain old data state carrier.
            _mbstate: unsafe { std::mem::zeroed() },
            open_flags,
            fingerprint,
            runtime_math_hooks: NativeFileRuntimeMathHooks::new(),
            popen_child_pid: None,
        }
    }

    /// Get the file descriptor if this is an fd-backed stream.
    #[allow(dead_code)] // WIP: used when native fmemopen is wired
    fn fd(&self) -> Option<c_int> {
        match &self.backing {
            NativeFileBacking::Fd(fd) => Some(*fd),
            _ => None,
        }
    }
}

struct NativeFileState {
    locked: Box<ReentrantMutex<RefCell<NativeFileLocked>>>,
    orientation: AtomicI8,
}

impl NativeFileState {
    fn new(fd: c_int, open_flags: u32, buf_mode: NativeFileBufMode) -> Self {
        Self {
            locked: Box::new(ReentrantMutex::new(RefCell::new(NativeFileLocked::new(
                fd, open_flags, buf_mode,
            )))),
            orientation: AtomicI8::new(0),
        }
    }

    fn new_with_backing(
        backing: NativeFileBacking,
        open_flags: u32,
        buf_mode: NativeFileBufMode,
    ) -> Self {
        Self {
            locked: Box::new(ReentrantMutex::new(RefCell::new(
                NativeFileLocked::new_with_backing(backing, open_flags, buf_mode),
            ))),
            orientation: AtomicI8::new(0),
        }
    }

    fn lock_ptr(&self) -> *mut c_void {
        (self.locked.as_ref() as *const ReentrantMutex<RefCell<NativeFileLocked>>).cast::<c_void>()
            as *mut c_void
    }
}

/// FrankenLibC-owned FILE structure.
///
/// The first 216 bytes exactly match glibc 2.34's `_IO_FILE` layout on
/// x86_64. A `_IO_jump_t` pointer then makes this a true `_IO_FILE_plus`,
/// and FrankenLibC-specific state lives behind that ABI-visible prefix.
#[repr(C)]
pub struct NativeFile {
    _io_file: _IO_FILE_Layout,
    pub vtable: *mut _IO_jump_t,
    _frankenlibc_state: NativeFileState,
}

/// Magic value identifying a [`NativeFile`] struct: "FKLC".
pub const NATIVE_FILE_MAGIC: u32 = 0x464b_4c43;

// Compile-time assertions: NativeFile must be at least as large as glibc FILE (216 bytes).
const _: () = assert!(
    std::mem::size_of::<_IO_FILE_Layout>() == GLIBC_234_IO_FILE_SIZE,
    "_IO_FILE_Layout must match glibc 2.34 FILE size"
);
const _: () = assert!(
    std::mem::offset_of!(NativeFile, vtable) == GLIBC_234_IO_FILE_PLUS_VTABLE_OFFSET,
    "NativeFile.vtable must sit immediately after the glibc _IO_FILE prefix"
);
const _: () = assert!(
    std::mem::size_of::<NativeFile>() <= 4096,
    "NativeFile must remain slab-friendly (<= 4096 bytes)"
);

impl NativeFile {
    /// Create a new `NativeFile` for the given file descriptor and flags.
    ///
    /// The vtable is automatically set to `NATIVE_IO_JUMP_T` for proper
    /// indirect dispatch support (e.g., for `-fno-plt` binaries).
    pub fn new(fd: i32, flags: u32, buf_mode: NativeFileBufMode) -> Self {
        let mut file = Self {
            _io_file: _IO_FILE_Layout::new(fd),
            // Set vtable to our native trampolines for indirect vtable dispatch.
            vtable: ptr::addr_of!(NATIVE_IO_JUMP_T) as *mut _IO_jump_t,
            _frankenlibc_state: NativeFileState::new(fd, flags, buf_mode),
        };
        file.sync_lock_ptr();
        file
    }

    /// Create a new `NativeFile` with custom backing storage.
    ///
    /// Used for memory-backed streams (fmemopen, open_memstream).
    #[allow(dead_code)] // WIP: used when native fmemopen is wired
    pub(crate) fn new_with_backing(
        backing: NativeFileBacking,
        flags: u32,
        buf_mode: NativeFileBufMode,
    ) -> Self {
        let mut file = Self {
            _io_file: _IO_FILE_Layout::new(-1), // Memory streams have no fd
            vtable: ptr::addr_of!(NATIVE_IO_JUMP_T) as *mut _IO_jump_t,
            _frankenlibc_state: NativeFileState::new_with_backing(backing, flags, buf_mode),
        };
        file.sync_lock_ptr();
        file
    }

    fn with_locked<R>(&self, f: impl FnOnce(&NativeFileLocked) -> R) -> R {
        let guard = self._frankenlibc_state.locked.lock();
        let state = guard.borrow();
        f(&state)
    }

    fn with_locked_mut<R>(&self, f: impl FnOnce(&mut NativeFileLocked) -> R) -> R {
        let guard = self._frankenlibc_state.locked.lock();
        let mut state = guard.borrow_mut();
        f(&mut state)
    }

    fn sync_glibc_buffer_head(&mut self, base: *mut u8, pos: *mut u8, end: *mut u8) {
        let base = base.cast::<c_char>();
        let pos = pos.cast::<c_char>();
        let end = end.cast::<c_char>();
        self._io_file._IO_buf_base = base;
        self._io_file._IO_buf_end = end;
        self._io_file._IO_read_base = base;
        self._io_file._IO_read_ptr = pos;
        self._io_file._IO_read_end = end;
        self._io_file._IO_write_base = base;
        self._io_file._IO_write_ptr = pos;
        self._io_file._IO_write_end = end;
    }

    fn sync_lock_ptr(&mut self) {
        self._io_file._lock = self._frankenlibc_state.lock_ptr();
    }

    pub fn invalidate(&mut self) {
        self.with_locked_mut(|state| {
            state.magic = 0;
            state.buffer_base = ptr::null_mut();
            state.buffer_pos = ptr::null_mut();
            state.buffer_end = ptr::null_mut();
            state.buffer_capacity = 0;
            state.eof = false;
            state.error = false;
            state.ungetc = None;
            state.open_flags = 0;
            state.generation = state.generation.saturating_add(1);
            state.healing_budget = 0;
            state.fingerprint = [0; 16];
            state.runtime_math_hooks = NativeFileRuntimeMathHooks::new();
        });
        self._io_file = _IO_FILE_Layout::new(-1);
        self._io_file._flags = 0;
        self.sync_lock_ptr();
        self.vtable = ptr::null_mut();
        self._frankenlibc_state
            .orientation
            .store(0, Ordering::Relaxed);
    }

    #[inline]
    pub fn magic(&self) -> u32 {
        self.with_locked(|state| state.magic)
    }

    #[inline]
    pub fn fd(&self) -> i32 {
        self._io_file._fileno
    }

    #[inline]
    pub fn set_fd(&mut self, fd: i32) {
        self._io_file._fileno = fd;
    }

    #[inline]
    pub fn offset(&self) -> i64 {
        self._io_file._offset
    }

    #[inline]
    pub fn set_offset(&mut self, offset: i64) {
        self._io_file._offset = offset;
        self._io_file._old_offset = offset as libc::off_t;
    }

    #[inline]
    pub fn buf_mode(&self) -> NativeFileBufMode {
        self.with_locked(|state| state.buf_mode)
    }

    #[inline]
    pub fn flags(&self) -> u32 {
        self.with_locked(|state| {
            let mut flags = state.open_flags;
            if state.eof {
                flags |= file_flags::EOF;
            }
            if state.error {
                flags |= file_flags::ERROR;
            }
            flags
        })
    }

    #[inline]
    pub fn buffer_base(&self) -> *mut u8 {
        self._io_file._IO_buf_base.cast::<u8>()
    }

    #[inline]
    pub fn buffer_pos(&self) -> *mut u8 {
        self._io_file._IO_write_ptr.cast::<u8>()
    }

    #[inline]
    pub fn buffer_end(&self) -> *mut u8 {
        self._io_file._IO_buf_end.cast::<u8>()
    }

    #[inline]
    pub fn buffer_size(&self) -> usize {
        self.with_locked(|state| state.buffer_capacity)
    }

    #[inline]
    pub fn set_buffer_state(&mut self, base: *mut u8, pos: *mut u8, end: *mut u8, size: usize) {
        self.with_locked_mut(|state| {
            state.buffer_base = base;
            state.buffer_pos = pos;
            state.buffer_end = end;
            state.buffer_capacity = size;
        });
        self.sync_glibc_buffer_head(base, pos, end);
    }

    #[inline]
    pub fn ungetc_value(&self) -> i16 {
        self.with_locked(|state| state.ungetc.map_or(-1, i16::from))
    }

    #[inline]
    pub fn set_ungetc_value(&mut self, value: i16) {
        self.with_locked_mut(|state| {
            state.ungetc = u8::try_from(value).ok();
        });
    }

    #[inline]
    pub fn lock_ptr(&self) -> *mut c_void {
        self._io_file._lock
    }

    /// Get the `_chain` pointer for linked-list traversal.
    #[inline]
    pub fn chain(&self) -> *mut NativeFile {
        self._io_file._chain.cast::<NativeFile>()
    }

    /// Set the `_chain` pointer for linked-list maintenance.
    #[inline]
    pub fn set_chain(&mut self, next: *mut NativeFile) {
        self._io_file._chain = next.cast::<_IO_FILE_Layout>();
    }

    /// Returns `true` if this struct has the correct magic value.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic() == NATIVE_FILE_MAGIC
    }

    /// Returns `true` if the EOF flag is set.
    #[inline]
    pub fn is_eof(&self) -> bool {
        self._io_file._flags & GLIBC_IO_EOF_SEEN != 0
    }

    /// Returns `true` if the error flag is set.
    #[inline]
    pub fn is_error(&self) -> bool {
        self._io_file._flags & GLIBC_IO_ERR_SEEN != 0
    }

    /// Set the EOF flag.
    #[inline]
    pub fn set_eof(&mut self) {
        self._io_file._flags |= GLIBC_IO_EOF_SEEN;
        self.with_locked_mut(|state| state.eof = true);
    }

    /// Set the error flag.
    #[inline]
    pub fn set_error(&mut self) {
        self._io_file._flags |= GLIBC_IO_ERR_SEEN;
        self.with_locked_mut(|state| state.error = true);
    }

    /// Clear both EOF and error flags (for `clearerr`).
    #[inline]
    pub fn clear_errors(&mut self) {
        self._io_file._flags &= !(GLIBC_IO_EOF_SEEN | GLIBC_IO_ERR_SEEN);
        self.with_locked_mut(|state| {
            state.eof = false;
            state.error = false;
        });
    }

    /// Clear only the EOF flag without disturbing the error bit.
    #[inline]
    pub fn clear_eof(&mut self) {
        self._io_file._flags &= !GLIBC_IO_EOF_SEEN;
        self.with_locked_mut(|state| state.eof = false);
    }

    /// Explicitly acquire the stream lock for flockfile().
    ///
    /// This increments the lock count. The caller must call `explicit_unlock()`
    /// for each `explicit_lock()` call to release the lock.
    ///
    /// # Safety
    /// The caller must ensure that `explicit_unlock()` is eventually called
    /// the same number of times to release the lock.
    #[inline]
    pub fn explicit_lock(&self) {
        let guard = self._frankenlibc_state.locked.lock();
        // Forget the guard to keep the lock held.
        std::mem::forget(guard);
    }

    /// Try to explicitly acquire the stream lock for ftrylockfile().
    ///
    /// Returns `true` if the lock was acquired, `false` if it would block.
    /// If successful, the caller must call `explicit_unlock()` to release.
    #[inline]
    pub fn try_explicit_lock(&self) -> bool {
        if let Some(guard) = self._frankenlibc_state.locked.try_lock() {
            std::mem::forget(guard);
            true
        } else {
            false
        }
    }

    /// Release an explicit lock acquired via `explicit_lock()` or `try_explicit_lock()`.
    ///
    /// # Safety
    /// The caller must have previously acquired the lock via `explicit_lock()` or
    /// a successful `try_explicit_lock()` call.
    #[inline]
    pub unsafe fn explicit_unlock(&self) {
        // Use parking_lot's lock_api trait to directly decrement the lock count.
        // The caller is responsible for ensuring the lock was previously acquired.
        use parking_lot::lock_api::RawMutex;
        unsafe {
            self._frankenlibc_state.locked.raw().unlock();
        }
    }

    /// Returns `true` if the stream is readable.
    #[inline]
    pub fn is_readable(&self) -> bool {
        self.with_locked(|state| state.open_flags & file_flags::READ != 0)
    }

    /// Returns `true` if the stream is writable.
    #[inline]
    pub fn is_writable(&self) -> bool {
        self.with_locked(|state| state.open_flags & file_flags::WRITE != 0)
    }

    /// Update the exported buffering metadata for externally visible FILE* globals.
    /// # Safety
    /// If `user_buf` is non-null, it must point to at least `size` bytes of valid memory.
    pub unsafe fn configure_buffering(
        &mut self,
        mode: NativeFileBufMode,
        user_buf: *mut u8,
        size: usize,
    ) {
        self.with_locked_mut(|state| {
            state.buf_mode = mode;
            state.buffer_capacity = size;
            if matches!(mode, NativeFileBufMode::None) || size == 0 || user_buf.is_null() {
                state.buffer_base = ptr::null_mut();
                state.buffer_pos = ptr::null_mut();
                state.buffer_end = ptr::null_mut();
                state.open_flags &= !file_flags::OWN_BUFFER;
            } else {
                state.buffer_base = user_buf;
                state.buffer_pos = user_buf;
                // SAFETY: caller provided a buffer pointer with `size` bytes of storage.
                state.buffer_end = unsafe { user_buf.add(size) };
                state.open_flags &= !file_flags::OWN_BUFFER;
            }
        });
        if matches!(mode, NativeFileBufMode::None) || size == 0 {
            self.sync_glibc_buffer_head(ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
            return;
        }

        if user_buf.is_null() {
            self.sync_glibc_buffer_head(ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
            return;
        }

        // SAFETY: caller provided a buffer pointer with `size` bytes of storage.
        let end = unsafe { user_buf.add(size) };
        self.sync_glibc_buffer_head(user_buf, user_buf, end);
    }

    /// Set the child PID for streams opened via `popen`.
    #[inline]
    pub fn set_popen_child_pid(&mut self, pid: i32) {
        self.with_locked_mut(|state| state.popen_child_pid = Some(pid));
    }

    /// Get and clear the popen child PID (used by `pclose`).
    ///
    /// Returns `Some(pid)` if this stream was opened via `popen`, `None` otherwise.
    #[inline]
    pub fn take_popen_child_pid(&mut self) -> Option<i32> {
        self.with_locked_mut(|state| state.popen_child_pid.take())
    }

    /// Returns true if this stream was opened via `popen`.
    #[inline]
    pub fn is_popen(&self) -> bool {
        self.with_locked(|state| state.popen_child_pid.is_some())
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
    let fd = unsafe { (*file).fd() };
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
    unsafe {
        let next = (*file).offset().saturating_add(n as i64);
        (*file).set_offset(next);
    }
    n
}

/// Write to the underlying fd via `SYS_write`.
///
/// # Safety
/// `file` must be a valid `NativeFile` pointer with a valid fd.
/// `buf` must be readable for `count` bytes.
unsafe fn vtable_fd_write(file: *mut NativeFile, buf: *const u8, count: usize) -> isize {
    let fd = unsafe { (*file).fd() };
    if fd < 0 {
        return -1;
    }
    let ret = unsafe { libc::syscall(libc::SYS_write, fd, buf, count) };
    if ret < 0 {
        unsafe { (*file).set_error() };
        return -1;
    }
    let n = ret as isize;
    unsafe {
        let next = (*file).offset().saturating_add(n as i64);
        (*file).set_offset(next);
    }
    n
}

/// Seek to a position via `SYS_lseek`.
///
/// # Safety
/// `file` must be a valid `NativeFile` pointer with a valid fd.
unsafe fn vtable_fd_seek(file: *mut NativeFile, offset: i64, whence: c_int) -> i64 {
    let fd = unsafe { (*file).fd() };
    if fd < 0 {
        return -1;
    }
    let ret = unsafe { libc::syscall(libc::SYS_lseek, fd, offset, whence) };
    if ret < 0 {
        unsafe { (*file).set_error() };
        return -1;
    }
    let new_offset = ret as i64;
    unsafe { (*file).set_offset(new_offset) };
    // Clear EOF on successful seek.
    unsafe {
        if (*file).is_eof() {
            (*file).clear_eof();
        }
    }
    new_offset
}

/// Close the underlying fd via `SYS_close` after flushing.
///
/// # Safety
/// `file` must be a valid `NativeFile` pointer.
unsafe fn vtable_fd_close(file: *mut NativeFile) -> c_int {
    // Flush any pending writes first.
    let flush_rc = unsafe { vtable_fd_flush(file) };
    let fd = unsafe { (*file).fd() };
    if fd < 0 {
        return if flush_rc != 0 { -1 } else { 0 };
    }
    let ret = unsafe { libc::syscall(libc::SYS_close, fd) };
    unsafe { (*file).set_fd(-1) };
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
    let base = unsafe { (*file).buffer_base() };
    let pos = unsafe { (*file).buffer_pos() };
    if base.is_null() || pos <= base {
        return 0; // Nothing to flush.
    }
    // Only flush if the stream is writable (buffered write data exists).
    if !unsafe { (*file).is_writable() } {
        return 0;
    }
    let fd = unsafe { (*file).fd() };
    if fd < 0 {
        return -1;
    }
    let pending = unsafe { pos.offset_from(base) } as usize;
    let mut written = 0usize;
    while written < pending {
        let ret =
            unsafe { libc::syscall(libc::SYS_write, fd, base.add(written), pending - written) };
        if ret < 0 {
            unsafe { (*file).set_error() };
            return -1;
        }
        written += ret as usize;
    }
    // Reset buffer position after flush.
    let size = unsafe { (*file).buffer_size() };
    unsafe { (*file).set_buffer_state(base, base, (*file).buffer_end(), size) };
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
    fn empty() -> Self {
        let mut file = NativeFile::new(-1, 0, NativeFileBufMode::None);
        file.invalidate();
        Self {
            state: SLOT_FREE,
            file,
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
            slots: std::array::from_fn(|_| StreamSlot::empty()),
        };
        // Pre-register stdin (fd 0), stdout (fd 1), stderr (fd 2).
        registry.slots[0] = StreamSlot {
            state: SLOT_OCCUPIED,
            file: {
                let mut file = NativeFile::new(0, file_flags::READ, NativeFileBufMode::Full);
                file.vtable = ptr::addr_of_mut!(_IO_file_jumps);
                file
            },
        };
        registry.slots[1] = StreamSlot {
            state: SLOT_OCCUPIED,
            file: {
                let mut file = NativeFile::new(1, file_flags::WRITE, NativeFileBufMode::Line);
                file.vtable = ptr::addr_of_mut!(_IO_file_jumps);
                file
            },
        };
        registry.slots[2] = StreamSlot {
            state: SLOT_OCCUPIED,
            file: {
                let mut file = NativeFile::new(2, file_flags::WRITE, NativeFileBufMode::None);
                file.vtable = ptr::addr_of_mut!(_IO_file_jumps);
                file
            },
        };
        // Note: Chain linking is deferred to ensure_stdio_chain_linked() because
        // the registry is moved after new() returns, invalidating any pointers.
        registry
    }

    /// Initialize the stdio chain links after the registry is in its final location.
    ///
    /// Must be called after the registry is placed in its final static location.
    /// This links stdin/stdout/stderr via _chain and sets _IO_list_all.
    fn ensure_stdio_chain_linked(&mut self) {
        // Get stable pointers to the stdio streams now that registry is in its final location.
        let stdin_ptr: *mut NativeFile = &mut self.slots[0].file;
        let stdout_ptr: *mut NativeFile = &mut self.slots[1].file;
        let stderr_ptr: *mut NativeFile = &mut self.slots[2].file;

        // Link stdio streams: stderr -> stdout -> stdin -> NULL
        self.slots[0].file.set_chain(ptr::null_mut()); // stdin: end of chain
        self.slots[1].file.set_chain(stdin_ptr); // stdout -> stdin
        self.slots[2].file.set_chain(stdout_ptr); // stderr -> stdout

        // SAFETY: _IO_list_all is only accessed within the registry mutex.
        unsafe {
            _IO_list_all = stderr_ptr.cast::<c_void>();
        }
    }

    /// Register a new stream. Returns the slot index, or `None` if full.
    ///
    /// The new file is prepended to the `_IO_list_all` linked list.
    pub fn register(&mut self, file: NativeFile) -> Option<usize> {
        // Start from slot 3 (0/1/2 are reserved for stdin/stdout/stderr).
        for i in 3..STREAM_REGISTRY_CAPACITY {
            if self.slots[i].state == SLOT_FREE {
                self.slots[i].state = SLOT_OCCUPIED;
                self.slots[i].file = file;
                // Link into _chain list: new file becomes the head.
                // SAFETY: _IO_list_all is protected by the registry mutex.
                let new_file_ptr: *mut NativeFile = &mut self.slots[i].file;
                unsafe {
                    let old_head = _IO_list_all.cast::<NativeFile>();
                    self.slots[i].file.set_chain(old_head);
                    _IO_list_all = new_file_ptr.cast::<c_void>();
                }
                return Some(i);
            }
        }
        None // Registry full.
    }

    /// Unregister a stream by slot index. Returns `true` if the slot was occupied.
    ///
    /// The file is unlinked from the `_IO_list_all` linked list.
    pub fn unregister(&mut self, index: usize) -> bool {
        if index >= STREAM_REGISTRY_CAPACITY || self.slots[index].state != SLOT_OCCUPIED {
            return false;
        }
        // Unlink from _chain list.
        let file_ptr: *mut NativeFile = &mut self.slots[index].file;
        // SAFETY: _IO_list_all is protected by the registry mutex.
        unsafe {
            let mut prev: *mut NativeFile = ptr::null_mut();
            let mut curr = _IO_list_all.cast::<NativeFile>();
            while !curr.is_null() {
                if curr == file_ptr {
                    // Found it. Unlink.
                    let next = (*curr).chain();
                    if prev.is_null() {
                        // Unlinking the head.
                        _IO_list_all = next.cast::<c_void>();
                    } else {
                        (*prev).set_chain(next);
                    }
                    break;
                }
                prev = curr;
                curr = (*curr).chain();
            }
        }
        self.slots[index] = StreamSlot::empty();
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
            if self.slots[i].state == SLOT_OCCUPIED && self.slots[i].file.is_writable() {
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

    /// Find the first occupied slot index (for `_IO_iter_begin`).
    pub fn first_occupied(&self) -> Option<usize> {
        self.slots.iter().position(|s| s.state == SLOT_OCCUPIED)
    }

    /// Find the next occupied slot index after `after` (for `_IO_iter_next`).
    pub fn next_occupied(&self, after: usize) -> Option<usize> {
        if after + 1 >= STREAM_REGISTRY_CAPACITY {
            return None;
        }
        self.slots[after + 1..]
            .iter()
            .position(|s| s.state == SLOT_OCCUPIED)
            .map(|offset| after + 1 + offset)
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

/// Flag to track if stdio chain has been initialized.
static STDIO_CHAIN_INITIALIZED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Access the global stream registry.
///
/// On first access, initializes the stdio chain links.
pub fn native_stream_registry() -> std::sync::MutexGuard<'static, NativeStreamRegistry> {
    let mut guard = NATIVE_STREAM_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    // Initialize stdio chain links on first access (after registry is in final location).
    if !STDIO_CHAIN_INITIALIZED.load(std::sync::atomic::Ordering::Acquire) {
        guard.ensure_stdio_chain_linked();
        STDIO_CHAIN_INITIALIZED.store(true, std::sync::atomic::Ordering::Release);
    }

    guard
}

pub fn native_stdio_stream_ptr(fd: c_int) -> *mut c_void {
    let index = match fd {
        libc::STDIN_FILENO => 0,
        libc::STDOUT_FILENO => 1,
        libc::STDERR_FILENO => 2,
        _ => return ptr::null_mut(),
    };
    let mut registry = native_stream_registry();
    let Some(file) = registry.get_mut(index) else {
        return ptr::null_mut();
    };
    file as *mut NativeFile as *mut c_void
}

/// # Safety
/// If `user_buf` is non-null, it must point to at least `size` bytes of valid memory.
pub unsafe fn configure_native_stdio_stream(
    fd: c_int,
    mode: NativeFileBufMode,
    user_buf: *mut u8,
    size: usize,
) -> bool {
    let index = match fd {
        libc::STDIN_FILENO => 0,
        libc::STDOUT_FILENO => 1,
        libc::STDERR_FILENO => 2,
        _ => return false,
    };
    let mut registry = native_stream_registry();
    let Some(file) = registry.get_mut(index) else {
        return false;
    };
    // SAFETY: caller guarantees `user_buf` (if non-null) has `size` bytes of storage.
    unsafe { file.configure_buffering(mode, user_buf, size) };
    true
}

// ---------------------------------------------------------------------------
// _IO_jump_t trampolines (bd-9chy.15)
// ---------------------------------------------------------------------------
//
// These extern "C" trampolines dispatch glibc vtable calls to our native
// stdio implementation. Each takes a FILE* (as *mut c_void), and calls the
// corresponding native stdio function.

/// Trampoline for `__finish`: finalize stream.
unsafe extern "C" fn trampoline_finish(fp: *mut c_void, _dummy: c_int) {
    // Called after fclose has flushed; we don't need to do anything extra.
    // The actual cleanup happens in fclose itself.
    let _ = fp;
}

/// Trampoline for `__overflow`: write buffer overflow or single char put.
unsafe extern "C" fn trampoline_overflow(fp: *mut c_void, ch: c_int) -> c_int {
    // Flush the buffer and then write the character if not EOF.
    if unsafe { stdio_abi::fflush(fp) } != 0 {
        return libc::EOF;
    }
    if ch == libc::EOF {
        return 0; // Just a flush request
    }
    // Write the single character
    unsafe { stdio_abi::fputc(ch, fp) }
}

/// Trampoline for `__underflow`: peek at next char (refill buffer, don't advance).
unsafe extern "C" fn trampoline_underflow(fp: *mut c_void) -> c_int {
    // Read a char and push it back
    let ch = unsafe { stdio_abi::fgetc(fp) };
    if ch != libc::EOF {
        let _ = unsafe { stdio_abi::ungetc(ch, fp) };
    }
    ch
}

/// Trampoline for `__uflow`: get next char (refill buffer, advance).
unsafe extern "C" fn trampoline_uflow(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fgetc(fp) }
}

/// Trampoline for `__pbackfail`: push back a character.
unsafe extern "C" fn trampoline_pbackfail(fp: *mut c_void, ch: c_int) -> c_int {
    if ch == libc::EOF {
        return libc::EOF;
    }
    unsafe { stdio_abi::ungetc(ch, fp) }
}

/// Trampoline for `__xsputn`: write multiple bytes.
unsafe extern "C" fn trampoline_xsputn(fp: *mut c_void, buf: *const c_void, n: usize) -> usize {
    unsafe { stdio_abi::fwrite(buf, 1, n, fp) }
}

/// Trampoline for `__xsgetn`: read multiple bytes.
unsafe extern "C" fn trampoline_xsgetn(fp: *mut c_void, buf: *mut c_void, n: usize) -> usize {
    unsafe { stdio_abi::fread(buf, 1, n, fp) }
}

/// Trampoline for `__seekoff`: seek relative to whence.
unsafe extern "C" fn trampoline_seekoff(
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

/// Trampoline for `__seekpos`: seek to absolute position.
unsafe extern "C" fn trampoline_seekpos(fp: *mut c_void, pos: i64, _mode: c_int) -> i64 {
    if unsafe { stdio_abi::fseeko(fp, pos, libc::SEEK_SET) } != 0 {
        return -1;
    }
    unsafe { stdio_abi::ftello(fp) }
}

/// Trampoline for `__setbuf`: set stream buffer.
unsafe extern "C" fn trampoline_setbuf(
    fp: *mut c_void,
    buf: *mut c_void,
    size: isize,
) -> *mut c_void {
    if size < 0 {
        return ptr::null_mut();
    }
    unsafe { stdio_abi::setbuffer(fp, buf.cast::<c_char>(), size as usize) };
    fp
}

/// Trampoline for `__sync`: synchronize buffer with fd.
unsafe extern "C" fn trampoline_sync(fp: *mut c_void) -> c_int {
    unsafe { stdio_abi::fflush(fp) }
}

/// Trampoline for `__doallocate`: allocate internal buffer.
unsafe extern "C" fn trampoline_doallocate(_fp: *mut c_void) -> c_int {
    // Our stdio layer handles buffer allocation lazily on first I/O.
    0 // success
}

/// Trampoline for `__read`: low-level read from fd.
///
/// This is a low-level vtable method called BY the buffered stdio layer
/// to perform raw I/O. It MUST use raw syscalls, not buffered stdio
/// (fread/fwrite), or infinite recursion would occur.
unsafe extern "C" fn trampoline_read(fp: *mut c_void, buf: *mut c_void, n: isize) -> isize {
    if n < 0 {
        return -1;
    }
    let fd = unsafe { stdio_abi::fileno(fp) };
    if fd < 0 {
        return -1;
    }
    // Use the raw-syscall-backed unistd helper, not buffered stdio.
    unsafe { crate::unistd_abi::sys_read_fd(fd, buf, n as usize) }
}

/// Trampoline for `__write`: low-level write to fd.
///
/// This is a low-level vtable method called BY the buffered stdio layer
/// to perform raw I/O. It MUST use raw syscalls, not buffered stdio,
/// or infinite recursion would occur.
unsafe extern "C" fn trampoline_write(fp: *mut c_void, buf: *const c_void, n: isize) -> isize {
    if n < 0 {
        return -1;
    }
    let fd = unsafe { stdio_abi::fileno(fp) };
    if fd < 0 {
        return -1;
    }
    // Use the raw-syscall-backed unistd helper, not buffered stdio.
    unsafe { crate::unistd_abi::sys_write_fd(fd, buf, n as usize) }
}

/// Trampoline for `__seek`: low-level lseek on fd.
///
/// This is a low-level vtable method. Use raw lseek syscall directly.
unsafe extern "C" fn trampoline_seek(fp: *mut c_void, offset: i64, dir: c_int) -> i64 {
    let fd = unsafe { stdio_abi::fileno(fp) };
    if fd < 0 {
        return -1;
    }
    // Route through the raw-syscall-backed lseek implementation.
    unsafe { crate::unistd_abi::lseek(fd, offset, dir) }
}

/// Trampoline for `__close`: close underlying fd.
///
/// CRITICAL: This is called BY fclose() to close the fd. We MUST NOT call
/// fclose() here or we'd cause infinite recursion / double-close.
/// Only close the raw fd.
unsafe extern "C" fn trampoline_close(fp: *mut c_void) -> c_int {
    let fd = unsafe { stdio_abi::fileno(fp) };
    if fd < 0 {
        return -1;
    }
    // Only close the raw fd; do not recurse through fclose.
    unsafe { crate::unistd_abi::close(fd) }
}

/// Trampoline for `__stat`: fstat underlying fd.
unsafe extern "C" fn trampoline_stat(fp: *mut c_void, st: *mut c_void) -> c_int {
    let fd = unsafe { stdio_abi::fileno(fp) };
    if fd < 0 {
        return -1;
    }
    unsafe { crate::unistd_abi::fstat(fd, st.cast::<libc::stat>()) }
}

/// Trampoline for `__showmanyc`: return available chars (rarely used).
unsafe extern "C" fn trampoline_showmanyc(_fp: *mut c_void) -> c_int {
    // Return -1 to indicate "unknown" (glibc default behavior).
    -1
}

/// Trampoline for `__imbue`: set locale (rarely used).
unsafe extern "C" fn trampoline_imbue(_fp: *mut c_void, _locale: *mut c_void) {
    // No-op: we don't track per-stream locale state.
}

/// The native `_IO_jump_t` vtable with all trampolines wired up.
///
/// This is the vtable that every `NativeFile` uses. It dispatches all
/// indirect vtable calls (e.g., from `-fno-plt` binaries) to our native
/// stdio implementation.
pub static NATIVE_IO_JUMP_T: _IO_jump_t = _IO_jump_t {
    __dummy: 0,
    __dummy2: 0,
    __finish: trampoline_finish,
    __overflow: trampoline_overflow,
    __underflow: trampoline_underflow,
    __uflow: trampoline_uflow,
    __pbackfail: trampoline_pbackfail,
    __xsputn: trampoline_xsputn,
    __xsgetn: trampoline_xsgetn,
    __seekoff: trampoline_seekoff,
    __seekpos: trampoline_seekpos,
    __setbuf: trampoline_setbuf,
    __sync: trampoline_sync,
    __doallocate: trampoline_doallocate,
    __read: trampoline_read,
    __write: trampoline_write,
    __seek: trampoline_seek,
    __close: trampoline_close,
    __stat: trampoline_stat,
    __showmanyc: trampoline_showmanyc,
    __imbue: trampoline_imbue,
};

// ---------------------------------------------------------------------------
// Global variable symbols
// ---------------------------------------------------------------------------

/// `_IO_list_all` — head of the linked list of all open FILE streams.
/// Native-owned: always points to our own list (null until streams are opened).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _IO_list_all: *mut c_void = std::ptr::null_mut();

/// `_IO_file_jumps` — default FILE vtable for regular files.
/// Native-owned: initialized with our native trampolines for full vtable dispatch.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _IO_file_jumps: _IO_jump_t = _IO_jump_t {
    __dummy: 0,
    __dummy2: 0,
    __finish: trampoline_finish,
    __overflow: trampoline_overflow,
    __underflow: trampoline_underflow,
    __uflow: trampoline_uflow,
    __pbackfail: trampoline_pbackfail,
    __xsputn: trampoline_xsputn,
    __xsgetn: trampoline_xsgetn,
    __seekoff: trampoline_seekoff,
    __seekpos: trampoline_seekpos,
    __setbuf: trampoline_setbuf,
    __sync: trampoline_sync,
    __doallocate: trampoline_doallocate,
    __read: trampoline_read,
    __write: trampoline_write,
    __seek: trampoline_seek,
    __close: trampoline_close,
    __stat: trampoline_stat,
    __showmanyc: trampoline_showmanyc,
    __imbue: trampoline_imbue,
};

/// `_IO_wfile_jumps` — default FILE vtable for wide-oriented files.
/// Native-owned: same trampolines as `_IO_file_jumps` (wide dispatch is TODO).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _IO_wfile_jumps: _IO_jump_t = _IO_jump_t {
    __dummy: 0,
    __dummy2: 0,
    __finish: trampoline_finish,
    __overflow: trampoline_overflow,
    __underflow: trampoline_underflow,
    __uflow: trampoline_uflow,
    __pbackfail: trampoline_pbackfail,
    __xsputn: trampoline_xsputn,
    __xsgetn: trampoline_xsgetn,
    __seekoff: trampoline_seekoff,
    __seekpos: trampoline_seekpos,
    __setbuf: trampoline_setbuf,
    __sync: trampoline_sync,
    __doallocate: trampoline_doallocate,
    __read: trampoline_read,
    __write: trampoline_write,
    __seek: trampoline_seek,
    __close: trampoline_close,
    __stat: trampoline_stat,
    __showmanyc: trampoline_showmanyc,
    __imbue: trampoline_imbue,
};

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

    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        line as usize,
        count as usize,
        false,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
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
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
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

    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        line as usize,
        (count as usize).saturating_mul(4), // wchar_t is 4 bytes
        false,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
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
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, false);
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

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Stdio, buf as usize, n, false, buf.is_null(), 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
        return -1;
    }

    let written = unsafe { stdio_abi::fwrite(buf as *const c_void, 1, n, fp) };
    let failed = written < n;
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, failed);
    if failed { -1 } else { 0 }
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
    if filename.is_null() || mode.is_null() {
        return std::ptr::null_mut();
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::IoFd, filename as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    let fp = unsafe { stdio_abi::fopen(filename, mode) };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, fp.is_null());
    fp
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
    if filename.is_null() {
        return std::ptr::null_mut();
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::IoFd, filename as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    let fd = unsafe {
        libc::syscall(libc::SYS_openat, libc::AT_FDCWD, filename, posix_mode, prot) as c_int
    };
    if fd < 0 {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
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
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, true);
    } else {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, false);
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

/// Iterator encoding: slot index + 1 as opaque pointer (bd-di5w).
/// Slot 0 (stdin) encodes as 1, slot 1 (stdout) as 2, etc.
/// End sentinel = STREAM_REGISTRY_CAPACITY + 1 = 257.
const IO_ITER_END_SENTINEL: usize = STREAM_REGISTRY_CAPACITY + 1;

/// Decode an iterator pointer to a slot index.
#[inline]
fn io_iter_decode(iter: *mut c_void) -> Option<usize> {
    let encoded = iter as usize;
    if encoded == 0 || encoded > STREAM_REGISTRY_CAPACITY {
        None
    } else {
        Some(encoded - 1)
    }
}

/// Encode a slot index as an iterator pointer.
#[inline]
fn io_iter_encode(slot: usize) -> *mut c_void {
    (slot + 1) as *mut c_void
}

/// `_IO_iter_begin` — get iterator to first FILE in the native stream list (bd-di5w).
///
/// Returns an opaque iterator pointing to the first occupied slot in the
/// `NativeStreamRegistry`, or the end sentinel if no streams are open.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_iter_begin() -> *mut c_void {
    let reg = native_stream_registry();
    match reg.first_occupied() {
        Some(slot) => io_iter_encode(slot),
        None => IO_ITER_END_SENTINEL as *mut c_void,
    }
}

/// `_IO_iter_end` — get end-of-list sentinel iterator (bd-di5w).
///
/// Returns a sentinel value that compares unequal to any valid iterator.
/// The iteration loop `for it = begin; it != end; it = next(it)` terminates
/// when all occupied slots have been visited.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_iter_end() -> *mut c_void {
    IO_ITER_END_SENTINEL as *mut c_void
}

/// `_IO_iter_file` — dereference iterator to get the FILE* it points to (bd-di5w).
///
/// Decodes the iterator to a slot index, looks up the `NativeFile` in the
/// registry, and returns a pointer to it. Returns NULL for invalid or
/// end-sentinel iterators.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_iter_file(iter: *mut c_void) -> *mut c_void {
    let Some(slot) = io_iter_decode(iter) else {
        return ptr::null_mut();
    };
    let mut reg = native_stream_registry();
    match reg.get_mut(slot) {
        Some(file) => file as *mut NativeFile as *mut c_void,
        None => ptr::null_mut(),
    }
}

/// `_IO_iter_next` — advance iterator to next occupied FILE slot (bd-di5w).
///
/// Scans forward from the current slot for the next occupied entry.
/// Returns the end sentinel when no more streams remain.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_iter_next(iter: *mut c_void) -> *mut c_void {
    let Some(current_slot) = io_iter_decode(iter) else {
        return IO_ITER_END_SENTINEL as *mut c_void;
    };
    let reg = native_stream_registry();
    match reg.next_occupied(current_slot) {
        Some(next_slot) => io_iter_encode(next_slot),
        None => IO_ITER_END_SENTINEL as *mut c_void,
    }
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
