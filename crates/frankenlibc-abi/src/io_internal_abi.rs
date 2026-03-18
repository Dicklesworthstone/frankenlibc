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
use std::sync::LazyLock;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::stdio_abi;

// ---------------------------------------------------------------------------
// Helper macro: resolve a glibc symbol via RTLD_NEXT, cache in LazyLock
// ---------------------------------------------------------------------------

macro_rules! io_resolve {
    ($sym:expr, $ty:ty) => {{
        static FUNC: LazyLock<Option<$ty>> = LazyLock::new(|| {
            let sym = unsafe { libc::dlsym(libc::RTLD_NEXT, $sym.as_ptr()) };
            if sym.is_null() {
                None
            } else {
                Some(unsafe { std::mem::transmute::<*mut c_void, $ty>(sym) })
            }
        });
        *FUNC
    }};
}

// ---------------------------------------------------------------------------
// Global variable symbols (exported as static AtomicPtr, lazily resolved)
// ---------------------------------------------------------------------------

// Sentinel value indicating "not yet resolved" (distinct from null, which means "not found").
const UNRESOLVED: *mut c_void = std::ptr::dangling_mut::<c_void>();

fn resolve_global(name: &std::ffi::CStr, slot: &AtomicPtr<c_void>) -> *mut c_void {
    let mut ptr = slot.load(Ordering::Acquire);
    if ptr == UNRESOLVED {
        ptr = unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr()) };
        // If dlsym returns null, the symbol wasn't found — store null.
        slot.store(ptr, Ordering::Release);
    }
    ptr
}

/// `_IO_list_all` — head of the linked list of all open FILE streams.
/// Lazily resolved from glibc on first access.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static _IO_list_all: AtomicPtr<c_void> = AtomicPtr::new(UNRESOLVED);

/// `_IO_file_jumps` — default FILE vtable for regular files.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static _IO_file_jumps: AtomicPtr<c_void> = AtomicPtr::new(UNRESOLVED);

/// `_IO_wfile_jumps` — default FILE vtable for wide-oriented files.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static _IO_wfile_jumps: AtomicPtr<c_void> = AtomicPtr::new(UNRESOLVED);

/// Accessor: resolve `_IO_list_all` from glibc on first call.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_list_all_get() -> *mut c_void {
    resolve_global(c"_IO_list_all", &_IO_list_all)
}

/// Accessor: resolve `_IO_file_jumps` from glibc on first call.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_jumps_get() -> *mut c_void {
    resolve_global(c"_IO_file_jumps", &_IO_file_jumps)
}

/// Accessor: resolve `_IO_wfile_jumps` from glibc on first call.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wfile_jumps_get() -> *mut c_void {
    resolve_global(c"_IO_wfile_jumps", &_IO_wfile_jumps)
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
            0x0A | 0x0D => c = 0,       // '\n' | '\r'
            0x09 => c = (c + 8) & !7,   // '\t'
            _ => c += 1,
        }
    }
    c as c_int
}

// ---------------------------------------------------------------------------
// Default vtable operations
// ---------------------------------------------------------------------------

/// `_IO_default_doallocate` — default buffer allocation for FILE.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_default_doallocate(fp: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void) -> c_int;
    match io_resolve!(c"_IO_default_doallocate", Fn) {
        Some(f) => unsafe { f(fp) },
        None => -1,
    }
}

/// `_IO_default_finish` — default finalization for FILE.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_default_finish(fp: *mut c_void, dummy: c_int) {
    type Fn = unsafe extern "C" fn(*mut c_void, c_int);
    if let Some(f) = io_resolve!(c"_IO_default_finish", Fn) {
        unsafe { f(fp, dummy) }
    }
}

/// `_IO_default_pbackfail` — default putback failure handler.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_default_pbackfail(fp: *mut c_void, ch: c_int) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
    match io_resolve!(c"_IO_default_pbackfail", Fn) {
        Some(f) => unsafe { f(fp, ch) },
        None => -1,
    }
}

/// `_IO_default_uflow` — default underflow-then-advance.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_default_uflow(fp: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void) -> c_int;
    match io_resolve!(c"_IO_default_uflow", Fn) {
        Some(f) => unsafe { f(fp) },
        None => -1,
    }
}

/// `_IO_default_xsgetn` — default multi-byte read.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_default_xsgetn(fp: *mut c_void, buf: *mut c_void, n: usize) -> usize {
    type Fn = unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> usize;
    match io_resolve!(c"_IO_default_xsgetn", Fn) {
        Some(f) => unsafe { f(fp, buf, n) },
        None => 0,
    }
}

/// `_IO_default_xsputn` — default multi-byte write.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_default_xsputn(
    fp: *mut c_void,
    buf: *const c_void,
    n: usize,
) -> usize {
    type Fn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> usize;
    match io_resolve!(c"_IO_default_xsputn", Fn) {
        Some(f) => unsafe { f(fp, buf, n) },
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Core I/O operations
// ---------------------------------------------------------------------------

/// `_IO_do_write` — flush write buffer to fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_do_write(fp: *mut c_void, buf: *const c_char, n: usize) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> c_int;
    match io_resolve!(c"_IO_do_write", Fn) {
        Some(f) => unsafe { f(fp, buf, n) },
        None => -1,
    }
}

/// `_IO_doallocbuf` — allocate FILE internal buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_doallocbuf(fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void);
    if let Some(f) = io_resolve!(c"_IO_doallocbuf", Fn) {
        unsafe { f(fp) }
    }
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_attach(fp: *mut c_void, fd: c_int) -> *mut c_void {
    type Fn = unsafe extern "C" fn(*mut c_void, c_int) -> *mut c_void;
    match io_resolve!(c"_IO_file_attach", Fn) {
        Some(f) => unsafe { f(fp, fd) },
        None => std::ptr::null_mut(),
    }
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_doallocate(fp: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void) -> c_int;
    match io_resolve!(c"_IO_file_doallocate", Fn) {
        Some(f) => unsafe { f(fp) },
        None => -1,
    }
}

/// `_IO_file_finish` — finalize file stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_finish(fp: *mut c_void, dummy: c_int) {
    type Fn = unsafe extern "C" fn(*mut c_void, c_int);
    if let Some(f) = io_resolve!(c"_IO_file_finish", Fn) {
        unsafe { f(fp, dummy) }
    }
}

/// `_IO_file_fopen` — open file by name into existing FILE.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_fopen(
    fp: *mut c_void,
    filename: *const c_char,
    mode: *const c_char,
    is32not64: c_int,
) -> *mut c_void {
    type Fn = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, c_int) -> *mut c_void;
    match io_resolve!(c"_IO_file_fopen", Fn) {
        Some(f) => unsafe { f(fp, filename, mode, is32not64) },
        None => std::ptr::null_mut(),
    }
}

/// `_IO_file_init` — initialize FILE structure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_init(fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void);
    if let Some(f) = io_resolve!(c"_IO_file_init", Fn) {
        unsafe { f(fp) }
    }
}

/// `_IO_file_open` — open file by name (low-level).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_open(
    fp: *mut c_void,
    filename: *const c_char,
    posix_mode: c_int,
    prot: c_int,
    read_write: c_int,
    is32not64: c_int,
) -> *mut c_void {
    type Fn =
        unsafe extern "C" fn(*mut c_void, *const c_char, c_int, c_int, c_int, c_int) -> *mut c_void;
    match io_resolve!(c"_IO_file_open", Fn) {
        Some(f) => unsafe { f(fp, filename, posix_mode, prot, read_write, is32not64) },
        None => std::ptr::null_mut(),
    }
}

/// `_IO_file_overflow` — handle write buffer overflow.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_file_overflow(fp: *mut c_void, ch: c_int) -> c_int {
    if ch == libc::EOF {
        if unsafe { stdio_abi::fflush(fp) } == 0 {
            0
        } else {
            libc::EOF
        }
    } else {
        unsafe { stdio_abi::fputc(ch, fp) }
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_flush_all_linebuffered() {
    type Fn = unsafe extern "C" fn();
    if let Some(f) = io_resolve!(c"_IO_flush_all_linebuffered", Fn) {
        unsafe { f() }
    }
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_free_backup_area(fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void);
    if let Some(f) = io_resolve!(c"_IO_free_backup_area", Fn) {
        unsafe { f(fp) }
    }
}

/// `_IO_free_wbackup_area` — free the wide backup read buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_free_wbackup_area(fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void);
    if let Some(f) = io_resolve!(c"_IO_free_wbackup_area", Fn) {
        unsafe { f(fp) }
    }
}

// ---------------------------------------------------------------------------
// Getline / gets
// ---------------------------------------------------------------------------

/// `_IO_getline` — read a line from FILE.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_getline(
    fp: *mut c_void,
    buf: *mut c_char,
    n: usize,
    delim: c_int,
    extract_delim: c_int,
) -> usize {
    type Fn = unsafe extern "C" fn(*mut c_void, *mut c_char, usize, c_int, c_int) -> usize;
    match io_resolve!(c"_IO_getline", Fn) {
        Some(f) => unsafe { f(fp, buf, n, delim, extract_delim) },
        None => 0,
    }
}

/// `_IO_getline_info` — read a line with extra info.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_getline_info(
    fp: *mut c_void,
    buf: *mut c_char,
    n: usize,
    delim: c_int,
    extract_delim: c_int,
    eof: *mut c_int,
) -> usize {
    type Fn =
        unsafe extern "C" fn(*mut c_void, *mut c_char, usize, c_int, c_int, *mut c_int) -> usize;
    match io_resolve!(c"_IO_getline_info", Fn) {
        Some(f) => unsafe { f(fp, buf, n, delim, extract_delim, eof) },
        None => 0,
    }
}

/// `_IO_gets` — internal gets (deprecated but exported).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_gets(buf: *mut c_char) -> *mut c_char {
    type Fn = unsafe extern "C" fn(*mut c_char) -> *mut c_char;
    match io_resolve!(c"_IO_gets", Fn) {
        Some(f) => unsafe { f(buf) },
        None => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// `_IO_init` — initialize an _IO_FILE structure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_init(fp: *mut c_void, flags: c_int) {
    type Fn = unsafe extern "C" fn(*mut c_void, c_int);
    if let Some(f) = io_resolve!(c"_IO_init", Fn) {
        unsafe { f(fp, flags) }
    }
}

// ---------------------------------------------------------------------------
// Marker operations
// ---------------------------------------------------------------------------

/// `_IO_init_marker` — initialize a stream position marker.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_init_marker(marker: *mut c_void, fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void, *mut c_void);
    if let Some(f) = io_resolve!(c"_IO_init_marker", Fn) {
        unsafe { f(marker, fp) }
    }
}

/// `_IO_init_wmarker` — initialize a wide stream position marker.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_init_wmarker(marker: *mut c_void, fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void, *mut c_void);
    if let Some(f) = io_resolve!(c"_IO_init_wmarker", Fn) {
        unsafe { f(marker, fp) }
    }
}

/// `_IO_marker_delta` — distance from marker to current position.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_marker_delta(marker: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void) -> c_int;
    match io_resolve!(c"_IO_marker_delta", Fn) {
        Some(f) => unsafe { f(marker) },
        None => 0,
    }
}

/// `_IO_marker_difference` — distance between two markers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_marker_difference(mark1: *mut c_void, mark2: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
    match io_resolve!(c"_IO_marker_difference", Fn) {
        Some(f) => unsafe { f(mark1, mark2) },
        None => 0,
    }
}

/// `_IO_remove_marker` — remove a stream position marker.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_remove_marker(marker: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void);
    if let Some(f) = io_resolve!(c"_IO_remove_marker", Fn) {
        unsafe { f(marker) }
    }
}

/// `_IO_seekmark` — seek to a marker position.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_seekmark(fp: *mut c_void, marker: *mut c_void, delta: c_int) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void, *mut c_void, c_int) -> c_int;
    match io_resolve!(c"_IO_seekmark", Fn) {
        Some(f) => unsafe { f(fp, marker, delta) },
        None => -1,
    }
}

/// `_IO_seekwmark` — seek to a wide marker position.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_seekwmark(
    fp: *mut c_void,
    marker: *mut c_void,
    delta: c_int,
) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void, *mut c_void, c_int) -> c_int;
    match io_resolve!(c"_IO_seekwmark", Fn) {
        Some(f) => unsafe { f(fp, marker, delta) },
        None => -1,
    }
}

/// `_IO_unsave_markers` — release all saved markers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_unsave_markers(fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void);
    if let Some(f) = io_resolve!(c"_IO_unsave_markers", Fn) {
        unsafe { f(fp) }
    }
}

/// `_IO_unsave_wmarkers` — release all saved wide markers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_unsave_wmarkers(fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void);
    if let Some(f) = io_resolve!(c"_IO_unsave_wmarkers", Fn) {
        unsafe { f(fp) }
    }
}

/// `_IO_least_wmarker` — find the leftmost wide marker.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_least_wmarker(fp: *mut c_void, end: *mut c_void) -> isize {
    type Fn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize;
    match io_resolve!(c"_IO_least_wmarker", Fn) {
        Some(f) => unsafe { f(fp, end) },
        None => 0,
    }
}

/// `_IO_wmarker_delta` — distance from wide marker to current position.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wmarker_delta(marker: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void) -> c_int;
    match io_resolve!(c"_IO_wmarker_delta", Fn) {
        Some(f) => unsafe { f(marker) },
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Iterator operations (FILE list traversal)
// ---------------------------------------------------------------------------

/// `_IO_iter_begin` — get iterator to first FILE in list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_iter_begin() -> *mut c_void {
    type Fn = unsafe extern "C" fn() -> *mut c_void;
    match io_resolve!(c"_IO_iter_begin", Fn) {
        Some(f) => unsafe { f() },
        None => std::ptr::null_mut(),
    }
}

/// `_IO_iter_end` — get sentinel iterator (end of list).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_iter_end() -> *mut c_void {
    type Fn = unsafe extern "C" fn() -> *mut c_void;
    match io_resolve!(c"_IO_iter_end", Fn) {
        Some(f) => unsafe { f() },
        None => std::ptr::null_mut(),
    }
}

/// `_IO_iter_file` — dereference iterator to get FILE*.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_iter_file(iter: *mut c_void) -> *mut c_void {
    type Fn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    match io_resolve!(c"_IO_iter_file", Fn) {
        Some(f) => unsafe { f(iter) },
        None => std::ptr::null_mut(),
    }
}

/// `_IO_iter_next` — advance iterator to next FILE.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_iter_next(iter: *mut c_void) -> *mut c_void {
    type Fn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    match io_resolve!(c"_IO_iter_next", Fn) {
        Some(f) => unsafe { f(iter) },
        None => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// List locking
// ---------------------------------------------------------------------------

/// `_IO_link_in` — add FILE to the global list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_link_in(fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void);
    if let Some(f) = io_resolve!(c"_IO_link_in", Fn) {
        unsafe { f(fp) }
    }
}

/// `_IO_un_link` — remove FILE from the global list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_un_link(fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void);
    if let Some(f) = io_resolve!(c"_IO_un_link", Fn) {
        unsafe { f(fp) }
    }
}

/// `_IO_list_lock` — lock the global FILE list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_list_lock() {
    type Fn = unsafe extern "C" fn();
    if let Some(f) = io_resolve!(c"_IO_list_lock", Fn) {
        unsafe { f() }
    }
}

/// `_IO_list_unlock` — unlock the global FILE list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_list_unlock() {
    type Fn = unsafe extern "C" fn();
    if let Some(f) = io_resolve!(c"_IO_list_unlock", Fn) {
        unsafe { f() }
    }
}

/// `_IO_list_resetlock` — reset the global FILE list lock.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_list_resetlock() {
    type Fn = unsafe extern "C" fn();
    if let Some(f) = io_resolve!(c"_IO_list_resetlock", Fn) {
        unsafe { f() }
    }
}

// ---------------------------------------------------------------------------
// popen / proc_open / proc_close
// ---------------------------------------------------------------------------

/// `_IO_popen` — internal popen.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_popen(command: *const c_char, mode: *const c_char) -> *mut c_void {
    type Fn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
    match io_resolve!(c"_IO_popen", Fn) {
        Some(f) => unsafe { f(command, mode) },
        None => std::ptr::null_mut(),
    }
}

/// `_IO_proc_open` — open a process pipe.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_proc_open(
    fp: *mut c_void,
    command: *const c_char,
    mode: *const c_char,
) -> *mut c_void {
    type Fn = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void;
    match io_resolve!(c"_IO_proc_open", Fn) {
        Some(f) => unsafe { f(fp, command, mode) },
        None => std::ptr::null_mut(),
    }
}

/// `_IO_proc_close` — close a process pipe.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_proc_close(fp: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void) -> c_int;
    match io_resolve!(c"_IO_proc_close", Fn) {
        Some(f) => unsafe { f(fp) },
        None => -1,
    }
}

// ---------------------------------------------------------------------------
// setb / setbuffer / setvbuf
// ---------------------------------------------------------------------------

/// `_IO_setb` — set base and end of internal buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_setb(
    fp: *mut c_void,
    base: *mut c_char,
    end: *mut c_char,
    user_buf: c_int,
) {
    type Fn = unsafe extern "C" fn(*mut c_void, *mut c_char, *mut c_char, c_int);
    if let Some(f) = io_resolve!(c"_IO_setb", Fn) {
        unsafe { f(fp, base, end, user_buf) }
    }
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_sputbackwc(fp: *mut c_void, wch: u32) -> u32 {
    type Fn = unsafe extern "C" fn(*mut c_void, u32) -> u32;
    match io_resolve!(c"_IO_sputbackwc", Fn) {
        Some(f) => unsafe { f(fp, wch) },
        None => 0xFFFF_FFFF, // WEOF
    }
}

/// `_IO_sungetc` — unget the last byte read.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_sungetc(fp: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void) -> c_int;
    match io_resolve!(c"_IO_sungetc", Fn) {
        Some(f) => unsafe { f(fp) },
        None => -1,
    }
}

/// `_IO_sungetwc` — unget the last wide character read.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_sungetwc(fp: *mut c_void) -> u32 {
    type Fn = unsafe extern "C" fn(*mut c_void) -> u32;
    match io_resolve!(c"_IO_sungetwc", Fn) {
        Some(f) => unsafe { f(fp) },
        None => 0xFFFF_FFFF, // WEOF
    }
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_str_init_readonly(fp: *mut c_void, str: *const c_char, len: usize) {
    type Fn = unsafe extern "C" fn(*mut c_void, *const c_char, usize);
    if let Some(f) = io_resolve!(c"_IO_str_init_readonly", Fn) {
        unsafe { f(fp, str, len) }
    }
}

/// `_IO_str_init_static` — initialize a static string stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_str_init_static(
    fp: *mut c_void,
    str: *mut c_char,
    len: usize,
    pstart: *mut c_char,
) {
    type Fn = unsafe extern "C" fn(*mut c_void, *mut c_char, usize, *mut c_char);
    if let Some(f) = io_resolve!(c"_IO_str_init_static", Fn) {
        unsafe { f(fp, str, len, pstart) }
    }
}

/// `_IO_str_overflow` — handle overflow for string stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_str_overflow(fp: *mut c_void, ch: c_int) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
    match io_resolve!(c"_IO_str_overflow", Fn) {
        Some(f) => unsafe { f(fp, ch) },
        None => -1,
    }
}

/// `_IO_str_pbackfail` — handle putback failure for string stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_str_pbackfail(fp: *mut c_void, ch: c_int) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
    match io_resolve!(c"_IO_str_pbackfail", Fn) {
        Some(f) => unsafe { f(fp, ch) },
        None => -1,
    }
}

/// `_IO_str_seekoff` — seek on string stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_str_seekoff(
    fp: *mut c_void,
    offset: i64,
    dir: c_int,
    mode: c_int,
) -> i64 {
    type Fn = unsafe extern "C" fn(*mut c_void, i64, c_int, c_int) -> i64;
    match io_resolve!(c"_IO_str_seekoff", Fn) {
        Some(f) => unsafe { f(fp, offset, dir, mode) },
        None => -1,
    }
}

/// `_IO_str_underflow` — handle underflow for string stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_str_underflow(fp: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void) -> c_int;
    match io_resolve!(c"_IO_str_underflow", Fn) {
        Some(f) => unsafe { f(fp) },
        None => -1,
    }
}

// ---------------------------------------------------------------------------
// Mode switching
// ---------------------------------------------------------------------------

/// `_IO_switch_to_get_mode` — switch FILE to read mode.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_switch_to_get_mode(fp: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void) -> c_int;
    match io_resolve!(c"_IO_switch_to_get_mode", Fn) {
        Some(f) => unsafe { f(fp) },
        None => -1,
    }
}

/// `_IO_switch_to_main_wget_area` — switch to main wide get area.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_switch_to_main_wget_area(fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void);
    if let Some(f) = io_resolve!(c"_IO_switch_to_main_wget_area", Fn) {
        unsafe { f(fp) }
    }
}

/// `_IO_switch_to_wbackup_area` — switch to wide backup area.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_switch_to_wbackup_area(fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void);
    if let Some(f) = io_resolve!(c"_IO_switch_to_wbackup_area", Fn) {
        unsafe { f(fp) }
    }
}

/// `_IO_switch_to_wget_mode` — switch FILE to wide read mode.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_switch_to_wget_mode(fp: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void) -> c_int;
    match io_resolve!(c"_IO_switch_to_wget_mode", Fn) {
        Some(f) => unsafe { f(fp) },
        None => -1,
    }
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

/// `_IO_vfscanf` — internal vfscanf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_vfscanf(
    fp: *mut c_void,
    fmt: *const c_char,
    ap: *mut c_void,
    errp: *mut c_int,
) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void, *mut c_int) -> c_int;
    match io_resolve!(c"_IO_vfscanf", Fn) {
        Some(f) => unsafe { f(fp, fmt, ap, errp) },
        None => -1,
    }
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdefault_doallocate(fp: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void) -> c_int;
    match io_resolve!(c"_IO_wdefault_doallocate", Fn) {
        Some(f) => unsafe { f(fp) },
        None => -1,
    }
}

/// `_IO_wdefault_finish` — default wide finalization.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdefault_finish(fp: *mut c_void, dummy: c_int) {
    type Fn = unsafe extern "C" fn(*mut c_void, c_int);
    if let Some(f) = io_resolve!(c"_IO_wdefault_finish", Fn) {
        unsafe { f(fp, dummy) }
    }
}

/// `_IO_wdefault_pbackfail` — default wide putback failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdefault_pbackfail(fp: *mut c_void, wch: u32) -> u32 {
    type Fn = unsafe extern "C" fn(*mut c_void, u32) -> u32;
    match io_resolve!(c"_IO_wdefault_pbackfail", Fn) {
        Some(f) => unsafe { f(fp, wch) },
        None => 0xFFFF_FFFF, // WEOF
    }
}

/// `_IO_wdefault_uflow` — default wide underflow-then-advance.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdefault_uflow(fp: *mut c_void) -> u32 {
    type Fn = unsafe extern "C" fn(*mut c_void) -> u32;
    match io_resolve!(c"_IO_wdefault_uflow", Fn) {
        Some(f) => unsafe { f(fp) },
        None => 0xFFFF_FFFF, // WEOF
    }
}

/// `_IO_wdefault_xsgetn` — default wide multi-byte read.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdefault_xsgetn(fp: *mut c_void, buf: *mut c_void, n: usize) -> usize {
    type Fn = unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> usize;
    match io_resolve!(c"_IO_wdefault_xsgetn", Fn) {
        Some(f) => unsafe { f(fp, buf, n) },
        None => 0,
    }
}

/// `_IO_wdefault_xsputn` — default wide multi-byte write.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdefault_xsputn(
    fp: *mut c_void,
    buf: *const c_void,
    n: usize,
) -> usize {
    type Fn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> usize;
    match io_resolve!(c"_IO_wdefault_xsputn", Fn) {
        Some(f) => unsafe { f(fp, buf, n) },
        None => 0,
    }
}

/// `_IO_wdo_write` — flush wide write buffer to fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdo_write(fp: *mut c_void, buf: *const c_void, n: usize) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> c_int;
    match io_resolve!(c"_IO_wdo_write", Fn) {
        Some(f) => unsafe { f(fp, buf, n) },
        None => -1,
    }
}

/// `_IO_wdoallocbuf` — allocate wide FILE internal buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wdoallocbuf(fp: *mut c_void) {
    type Fn = unsafe extern "C" fn(*mut c_void);
    if let Some(f) = io_resolve!(c"_IO_wdoallocbuf", Fn) {
        unsafe { f(fp) }
    }
}

// ---------------------------------------------------------------------------
// Wide file vtable operations
// ---------------------------------------------------------------------------

/// `_IO_wfile_overflow` — handle wide write buffer overflow.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wfile_overflow(fp: *mut c_void, wch: u32) -> u32 {
    type Fn = unsafe extern "C" fn(*mut c_void, u32) -> u32;
    match io_resolve!(c"_IO_wfile_overflow", Fn) {
        Some(f) => unsafe { f(fp, wch) },
        None => 0xFFFF_FFFF, // WEOF
    }
}

/// `_IO_wfile_seekoff` — seek on wide file.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wfile_seekoff(
    fp: *mut c_void,
    offset: i64,
    dir: c_int,
    mode: c_int,
) -> i64 {
    type Fn = unsafe extern "C" fn(*mut c_void, i64, c_int, c_int) -> i64;
    match io_resolve!(c"_IO_wfile_seekoff", Fn) {
        Some(f) => unsafe { f(fp, offset, dir, mode) },
        None => -1,
    }
}

/// `_IO_wfile_sync` — synchronize wide FILE buffer with fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wfile_sync(fp: *mut c_void) -> c_int {
    type Fn = unsafe extern "C" fn(*mut c_void) -> c_int;
    match io_resolve!(c"_IO_wfile_sync", Fn) {
        Some(f) => unsafe { f(fp) },
        None => -1,
    }
}

/// `_IO_wfile_underflow` — handle wide read buffer underflow.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wfile_underflow(fp: *mut c_void) -> u32 {
    type Fn = unsafe extern "C" fn(*mut c_void) -> u32;
    match io_resolve!(c"_IO_wfile_underflow", Fn) {
        Some(f) => unsafe { f(fp) },
        None => 0xFFFF_FFFF, // WEOF
    }
}

/// `_IO_wfile_xsputn` — multi-byte write for wide file stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wfile_xsputn(fp: *mut c_void, buf: *const c_void, n: usize) -> usize {
    type Fn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> usize;
    match io_resolve!(c"_IO_wfile_xsputn", Fn) {
        Some(f) => unsafe { f(fp, buf, n) },
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Wide buffer control
// ---------------------------------------------------------------------------

/// `_IO_wsetb` — set base and end of wide internal buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _IO_wsetb(
    fp: *mut c_void,
    base: *mut c_void,
    end: *mut c_void,
    user_buf: c_int,
) {
    type Fn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, c_int);
    if let Some(f) = io_resolve!(c"_IO_wsetb", Fn) {
        unsafe { f(fp, base, end, user_buf) }
    }
}
