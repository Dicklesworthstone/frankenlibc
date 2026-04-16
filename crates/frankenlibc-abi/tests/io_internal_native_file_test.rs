#![cfg(target_os = "linux")]

//! Integration tests for the native `_IO_FILE_plus`-shaped stdio substrate.

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use frankenlibc_abi::io_internal_abi::{
    _IO_iter_begin, _IO_iter_end, _IO_iter_file, _IO_iter_next, DEFAULT_FD_VTABLE,
    NATIVE_FILE_MAGIC, NATIVE_IO_JUMP_T, NativeFile, NativeFileBufMode, NativeFileVtable,
    file_flags, native_stream_registry,
};
use frankenlibc_core::syscall as raw_syscall;

#[allow(non_snake_case)]
#[repr(C)]
struct IoFileProjection {
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
    _chain: *mut IoFileProjection,
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
    _freeres_list: *mut IoFileProjection,
    _freeres_buf: *mut c_void,
    _pad5: usize,
    _mode: c_int,
    _unused2: [u8; 20],
}

#[repr(C)]
struct IoFilePlusProjection {
    file: IoFileProjection,
    vtable: *mut c_void,
}

// ---------------------------------------------------------------------------
// Size and layout
// ---------------------------------------------------------------------------

#[test]
fn native_file_size_at_least_glibc() {
    assert!(
        std::mem::size_of::<NativeFile>() >= 216,
        "NativeFile ({} bytes) must be >= 216 (glibc FILE)",
        std::mem::size_of::<NativeFile>()
    );
}

#[test]
fn native_file_is_repr_c() {
    assert!(std::mem::align_of::<NativeFile>() >= 4);
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

#[test]
fn native_file_construct_for_fd() {
    let f = NativeFile::new(3, file_flags::READ, NativeFileBufMode::Full);
    assert!(f.is_valid());
    assert_eq!(f.magic(), NATIVE_FILE_MAGIC);
    assert_eq!(f.fd(), 3);
    assert!(f.is_readable());
    assert!(!f.is_writable());
    assert!(!f.is_eof());
    assert!(!f.is_error());
    assert_eq!(f.buf_mode(), NativeFileBufMode::Full);
    assert!(f.buffer_base().is_null());
    assert_eq!(f.buffer_size(), 0);
    assert_eq!(f.offset(), 0);
    assert!(!f.vtable.is_null());
    assert_eq!(
        f.vtable as *const c_void,
        ptr::addr_of!(NATIVE_IO_JUMP_T) as *const c_void
    );
    assert!(!f.lock_ptr().is_null());
    assert_eq!(f.ungetc_value(), -1);
}

// ---------------------------------------------------------------------------
// Flag operations
// ---------------------------------------------------------------------------

#[test]
fn native_file_write_flags() {
    let f = NativeFile::new(
        1,
        file_flags::WRITE | file_flags::APPEND,
        NativeFileBufMode::Line,
    );
    assert!(f.is_writable());
    assert!(!f.is_readable());
    assert_eq!(f.flags() & file_flags::APPEND, file_flags::APPEND);
    assert_eq!(f.buf_mode(), NativeFileBufMode::Line);
}

#[test]
fn native_file_readwrite_flags() {
    let f = NativeFile::new(
        4,
        file_flags::READ | file_flags::WRITE,
        NativeFileBufMode::Full,
    );
    assert!(f.is_readable());
    assert!(f.is_writable());
}

#[test]
fn native_file_eof_and_error_flags() {
    let mut f = NativeFile::new(0, file_flags::READ, NativeFileBufMode::None);
    assert!(!f.is_eof());
    assert!(!f.is_error());

    f.set_eof();
    assert!(f.is_eof());
    assert!(!f.is_error());

    f.set_error();
    assert!(f.is_eof());
    assert!(f.is_error());

    f.clear_errors();
    assert!(!f.is_eof());
    assert!(!f.is_error());
}

// ---------------------------------------------------------------------------
// Buffer state
// ---------------------------------------------------------------------------

#[test]
fn native_file_buffer_state() {
    let mut f = NativeFile::new(5, file_flags::READ, NativeFileBufMode::Full);
    assert!(f.buffer_base().is_null());
    assert_eq!(f.buffer_size(), 0);

    let mut buf = [0u8; 4096];
    let base = buf.as_mut_ptr();
    let end = unsafe { base.add(buf.len()) };
    f.set_buffer_state(base, base, end, buf.len());

    assert!(!f.buffer_base().is_null());
    assert_eq!(f.buffer_size(), 4096);
    assert_eq!(f.buffer_pos(), f.buffer_base());
    assert_eq!(f.buffer_end(), end);
}

#[test]
fn native_file_glibc_prefix_cast_tracks_file_fields() {
    assert_eq!(std::mem::size_of::<IoFileProjection>(), 216);
    assert_eq!(std::mem::offset_of!(IoFilePlusProjection, vtable), 216);

    let mut f = NativeFile::new(
        7,
        file_flags::READ | file_flags::WRITE,
        NativeFileBufMode::Full,
    );
    let mut buf = [0u8; 64];
    let base = buf.as_mut_ptr();
    let pos = unsafe { base.add(11) };
    let end = unsafe { base.add(buf.len()) };
    f.set_buffer_state(base, pos, end, buf.len());
    f.set_offset(91);
    f.set_eof();

    let file_ptr = (&mut f as *mut NativeFile).cast::<libc::FILE>();
    let projected = unsafe { &*(file_ptr.cast::<IoFilePlusProjection>()) };

    assert_eq!(projected.file._fileno, 7);
    assert_eq!(projected.file._IO_buf_base, base.cast::<c_char>());
    assert_eq!(projected.file._IO_write_ptr, pos.cast::<c_char>());
    assert_eq!(projected.file._IO_buf_end, end.cast::<c_char>());
    assert_eq!(projected.file._offset, 91);
    assert_ne!(
        projected.file._flags & 0x0010,
        0,
        "EOF bit should be visible"
    );
    assert_eq!(
        projected.vtable as *const c_void,
        ptr::addr_of!(NATIVE_IO_JUMP_T) as *const c_void
    );
}

// ---------------------------------------------------------------------------
// Special fd values
// ---------------------------------------------------------------------------

#[test]
fn native_file_closed_fd() {
    let f = NativeFile::new(-1, 0, NativeFileBufMode::None);
    assert!(f.is_valid());
    assert_eq!(f.fd(), -1);
    assert!(!f.is_readable());
    assert!(!f.is_writable());
}

#[test]
fn native_file_memory_backed_fd() {
    let f = NativeFile::new(
        -2,
        file_flags::READ | file_flags::WRITE,
        NativeFileBufMode::Full,
    );
    assert!(f.is_valid());
    assert_eq!(f.fd(), -2);
    assert!(f.is_readable());
    assert!(f.is_writable());
}

// ---------------------------------------------------------------------------
// Magic validation
// ---------------------------------------------------------------------------

#[test]
fn native_file_invalid_magic() {
    let mut f = NativeFile::new(0, 0, NativeFileBufMode::None);
    assert!(f.is_valid());
    f.invalidate();
    assert!(!f.is_valid());
}

// ---------------------------------------------------------------------------
// Buffering modes
// ---------------------------------------------------------------------------

#[test]
fn native_file_unbuffered_mode() {
    let f = NativeFile::new(2, file_flags::WRITE, NativeFileBufMode::None);
    assert_eq!(f.buf_mode(), NativeFileBufMode::None);
}

#[test]
fn native_file_line_buffered_mode() {
    let f = NativeFile::new(1, file_flags::WRITE, NativeFileBufMode::Line);
    assert_eq!(f.buf_mode(), NativeFileBufMode::Line);
}

// ---------------------------------------------------------------------------
// ungetc buffer
// ---------------------------------------------------------------------------

#[test]
fn native_file_ungetc_buf_initially_empty() {
    let f = NativeFile::new(0, file_flags::READ, NativeFileBufMode::Full);
    assert_eq!(f.ungetc_value(), -1);
}

#[test]
fn native_file_ungetc_buf_stores_byte() {
    let mut f = NativeFile::new(0, file_flags::READ, NativeFileBufMode::Full);
    f.set_ungetc_value(b'A' as i16);
    assert_eq!(f.ungetc_value(), 65);
}

// ===========================================================================
// NativeFileVtable tests
// ===========================================================================

fn temp_memfd() -> c_int {
    let name = b"vtable_test\0";
    let fd = unsafe { raw_syscall::sys_memfd_create(name.as_ptr(), 0) }.expect("memfd_create");
    assert!(fd >= 0, "memfd_create failed");
    fd
}

#[test]
fn vtable_default_has_all_fields() {
    let _read = DEFAULT_FD_VTABLE.read;
    let _write = DEFAULT_FD_VTABLE.write;
    let _seek = DEFAULT_FD_VTABLE.seek;
    let _close = DEFAULT_FD_VTABLE.close;
    let _flush = DEFAULT_FD_VTABLE.flush;
}

#[test]
fn vtable_struct_size() {
    assert_eq!(
        std::mem::size_of::<NativeFileVtable>(),
        5 * std::mem::size_of::<usize>()
    );
}

#[test]
fn vtable_write_and_read_roundtrip() {
    let fd = temp_memfd();
    let mut f = NativeFile::new(
        fd,
        file_flags::WRITE | file_flags::READ,
        NativeFileBufMode::None,
    );
    let vtable = &DEFAULT_FD_VTABLE;

    let data = b"Hello, vtable!";
    let written = unsafe { (vtable.write)(&mut f, data.as_ptr(), data.len()) };
    assert_eq!(
        written,
        data.len() as isize,
        "write should return bytes written"
    );
    assert_eq!(f.offset(), data.len() as i64, "offset should advance");
    assert!(!f.is_error());

    let pos = unsafe { (vtable.seek)(&mut f, 0, libc::SEEK_SET) };
    assert_eq!(pos, 0, "seek to beginning should return 0");
    assert_eq!(f.offset(), 0);

    let mut buf = [0u8; 64];
    let read = unsafe { (vtable.read)(&mut f, buf.as_mut_ptr(), buf.len()) };
    assert_eq!(read, data.len() as isize, "read should return same bytes");
    assert_eq!(&buf[..data.len()], data);
    assert_eq!(f.offset(), data.len() as i64);

    let rc = unsafe { (vtable.close)(&mut f) };
    assert_eq!(rc, 0, "close should succeed");
    assert_eq!(f.fd(), -1, "fd should be -1 after close");
}

#[test]
fn vtable_read_eof() {
    let fd = temp_memfd();
    let mut f = NativeFile::new(fd, file_flags::READ, NativeFileBufMode::None);
    let vtable = &DEFAULT_FD_VTABLE;

    let mut buf = [0u8; 16];
    let read = unsafe { (vtable.read)(&mut f, buf.as_mut_ptr(), buf.len()) };
    assert_eq!(read, 0, "reading empty fd should return 0");
    assert!(f.is_eof(), "EOF flag should be set");

    unsafe { (vtable.close)(&mut f) };
}

#[test]
fn vtable_seek_end() {
    let fd = temp_memfd();
    let mut f = NativeFile::new(
        fd,
        file_flags::WRITE | file_flags::READ,
        NativeFileBufMode::None,
    );
    let vtable = &DEFAULT_FD_VTABLE;

    let data = b"0123456789";
    unsafe { (vtable.write)(&mut f, data.as_ptr(), data.len()) };

    let pos = unsafe { (vtable.seek)(&mut f, 0, libc::SEEK_END) };
    assert_eq!(pos, 10, "SEEK_END should be at byte 10");

    let pos = unsafe { (vtable.seek)(&mut f, -5, libc::SEEK_CUR) };
    assert_eq!(pos, 5, "SEEK_CUR -5 from 10 should be 5");

    unsafe { (vtable.close)(&mut f) };
}

#[test]
fn vtable_seek_clears_eof() {
    let fd = temp_memfd();
    let mut f = NativeFile::new(fd, file_flags::READ, NativeFileBufMode::None);
    let vtable = &DEFAULT_FD_VTABLE;

    let mut buf = [0u8; 1];
    unsafe { (vtable.read)(&mut f, buf.as_mut_ptr(), 1) };
    assert!(f.is_eof());

    unsafe { (vtable.seek)(&mut f, 0, libc::SEEK_SET) };
    assert!(!f.is_eof(), "seek should clear EOF");

    unsafe { (vtable.close)(&mut f) };
}

#[test]
fn vtable_flush_writes_buffer() {
    let fd = temp_memfd();
    let mut f = NativeFile::new(
        fd,
        file_flags::WRITE | file_flags::READ,
        NativeFileBufMode::Full,
    );
    let vtable = &DEFAULT_FD_VTABLE;

    let mut buf = [0u8; 128];
    let data = b"buffered data";
    buf[..data.len()].copy_from_slice(data);
    let base = buf.as_mut_ptr();
    let pos = unsafe { base.add(data.len()) };
    let end = unsafe { base.add(buf.len()) };
    f.set_buffer_state(base, pos, end, buf.len());

    let rc = unsafe { (vtable.flush)(&mut f) };
    assert_eq!(rc, 0, "flush should succeed");
    assert_eq!(
        f.buffer_pos(),
        f.buffer_base(),
        "buffer_pos should reset after flush"
    );
    assert!(!f.is_error());

    assert_eq!(raw_syscall::sys_lseek(fd, 0, libc::SEEK_SET), Ok(0));

    let mut read_buf = [0u8; 64];
    let n = unsafe { raw_syscall::sys_read(fd, read_buf.as_mut_ptr(), 64) };
    assert_eq!(n, Ok(data.len()));
    assert_eq!(&read_buf[..data.len()], data);

    assert_eq!(raw_syscall::sys_close(fd), Ok(()));
}

#[test]
fn vtable_close_flushes_before_closing() {
    let fd = temp_memfd();
    let mut f = NativeFile::new(fd, file_flags::WRITE, NativeFileBufMode::Full);
    let vtable = &DEFAULT_FD_VTABLE;

    let layout = std::alloc::Layout::from_size_align(256, 8).unwrap();
    let heap_buf = unsafe { std::alloc::alloc(layout) };
    assert!(!heap_buf.is_null());

    let data = b"close-flush test";
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), heap_buf, data.len()) };
    let pos = unsafe { heap_buf.add(data.len()) };
    let end = unsafe { heap_buf.add(256) };
    f.set_buffer_state(heap_buf, pos, end, 256);

    let verify_fd = raw_syscall::sys_dup(fd).expect("dup");
    assert!(verify_fd >= 0);

    let rc = unsafe { (vtable.close)(&mut f) };
    assert_eq!(rc, 0);
    assert_eq!(f.fd(), -1);

    assert_eq!(raw_syscall::sys_lseek(verify_fd, 0, libc::SEEK_SET), Ok(0));
    let mut read_buf = [0u8; 64];
    let n = unsafe { raw_syscall::sys_read(verify_fd, read_buf.as_mut_ptr(), 64) };
    assert_eq!(n, Ok(data.len()));
    assert_eq!(&read_buf[..data.len()], data);

    assert_eq!(raw_syscall::sys_close(verify_fd), Ok(()));
    unsafe { std::alloc::dealloc(heap_buf, layout) };
}

#[test]
fn vtable_read_invalid_fd_returns_error() {
    let mut f = NativeFile::new(-1, file_flags::READ, NativeFileBufMode::None);
    let vtable = &DEFAULT_FD_VTABLE;

    let mut buf = [0u8; 16];
    let ret = unsafe { (vtable.read)(&mut f, buf.as_mut_ptr(), buf.len()) };
    assert_eq!(ret, -1, "read on invalid fd should return -1");
}

#[test]
fn vtable_write_invalid_fd_returns_error() {
    let mut f = NativeFile::new(-1, file_flags::WRITE, NativeFileBufMode::None);
    let vtable = &DEFAULT_FD_VTABLE;

    let data = b"test";
    let ret = unsafe { (vtable.write)(&mut f, data.as_ptr(), data.len()) };
    assert_eq!(ret, -1, "write on invalid fd should return -1");
}

// ===========================================================================
// NativeStreamRegistry tests
// ===========================================================================

static REGISTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn registry_pre_registers_stdio() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let reg = native_stream_registry();

    let stdin = reg.get(0).expect("stdin should be pre-registered");
    assert_eq!(stdin.fd(), 0);
    assert!(stdin.is_readable());

    let stdout = reg.get(1).expect("stdout should be pre-registered");
    assert_eq!(stdout.fd(), 1);
    assert!(stdout.is_writable());

    let stderr = reg.get(2).expect("stderr should be pre-registered");
    assert_eq!(stderr.fd(), 2);
    assert!(stderr.is_writable());
}

#[test]
fn registry_register_and_get() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let mut reg = native_stream_registry();

    let f = NativeFile::new(42, file_flags::READ, NativeFileBufMode::Full);
    let slot = reg.register(f).expect("should register");
    assert!(slot >= 3, "slot should be >= 3 (0/1/2 are stdio)");

    let stream = reg.get(slot).expect("should find registered stream");
    assert_eq!(stream.fd(), 42);
    assert!(stream.is_valid());

    reg.unregister(slot);
}

#[test]
fn registry_unregister() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let mut reg = native_stream_registry();

    let f = NativeFile::new(99, file_flags::WRITE, NativeFileBufMode::None);
    let slot = reg.register(f).expect("should register");

    assert!(reg.get(slot).is_some());
    assert!(reg.unregister(slot));
    assert!(reg.get(slot).is_none());
    assert!(!reg.unregister(slot));
}

#[test]
fn registry_register_multiple_and_count() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let mut reg = native_stream_registry();
    let initial_count = reg.open_count();

    let mut slots = Vec::new();
    for i in 0..10 {
        let f = NativeFile::new(
            100 + i,
            file_flags::READ | file_flags::WRITE,
            NativeFileBufMode::Full,
        );
        let slot = reg.register(f).expect("should register");
        slots.push(slot);
    }

    assert_eq!(reg.open_count(), initial_count + 10);

    let unique: std::collections::HashSet<_> = slots.iter().collect();
    assert_eq!(unique.len(), 10);

    for (i, &slot) in slots.iter().enumerate() {
        let stream = reg.get(slot).unwrap();
        assert_eq!(stream.fd(), 100 + i as i32);
    }

    for slot in slots {
        reg.unregister(slot);
    }
}

#[test]
fn registry_get_mut_modifies_stream() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let mut reg = native_stream_registry();

    let f = NativeFile::new(50, file_flags::READ, NativeFileBufMode::Full);
    let slot = reg.register(f).expect("should register");

    {
        let stream = reg.get_mut(slot).unwrap();
        stream.set_eof();
        stream.set_offset(12345);
    }

    let stream = reg.get(slot).unwrap();
    assert!(stream.is_eof());
    assert_eq!(stream.offset(), 12345);

    reg.unregister(slot);
}

#[test]
fn registry_slot_reuse_after_unregister() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let mut reg = native_stream_registry();

    let f1 = NativeFile::new(70, file_flags::READ, NativeFileBufMode::None);
    let slot1 = reg.register(f1).expect("should register");
    reg.unregister(slot1);

    let f2 = NativeFile::new(71, file_flags::WRITE, NativeFileBufMode::Line);
    let slot2 = reg.register(f2).expect("should register");
    assert!(slot2 <= slot1, "freed slot should be reused");

    let stream = reg.get(slot2).unwrap();
    assert_eq!(stream.fd(), 71);

    reg.unregister(slot2);
}

#[test]
fn registry_get_out_of_bounds_returns_none() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let reg = native_stream_registry();

    assert!(reg.get(999).is_none());
    assert!(reg.get(usize::MAX).is_none());
}

#[test]
fn registry_flush_all_flushes_writable_streams() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let mut reg = native_stream_registry();

    let fd = temp_memfd();
    let mut f = NativeFile::new(fd, file_flags::WRITE, NativeFileBufMode::Full);

    let layout = std::alloc::Layout::from_size_align(128, 8).unwrap();
    let heap_buf = unsafe { std::alloc::alloc(layout) };
    assert!(!heap_buf.is_null());
    let data = b"flush_all test";
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), heap_buf, data.len()) };
    let pos = unsafe { heap_buf.add(data.len()) };
    let end = unsafe { heap_buf.add(128) };
    f.set_buffer_state(heap_buf, pos, end, 128);

    let slot = reg.register(f).expect("should register");

    let errors = reg.flush_all();
    assert_eq!(errors, 0, "flush_all should succeed");

    assert_eq!(raw_syscall::sys_lseek(fd, 0, libc::SEEK_SET), Ok(0));
    let mut read_buf = [0u8; 64];
    let n = unsafe { raw_syscall::sys_read(fd, read_buf.as_mut_ptr(), 64) };
    assert_eq!(n, Ok(data.len()));
    assert_eq!(&read_buf[..data.len()], data);

    if let Some(stream) = reg.get_mut(slot) {
        stream.set_buffer_state(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        );
    }
    reg.unregister(slot);
    assert_eq!(raw_syscall::sys_close(fd), Ok(()));
    unsafe { std::alloc::dealloc(heap_buf, layout) };
}

// ===========================================================================
// _IO_iter_* stream iterator tests
// ===========================================================================

#[test]
fn iter_begin_returns_first_stream() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let begin = unsafe { _IO_iter_begin() };
    let end = unsafe { _IO_iter_end() };
    assert_ne!(
        begin, end,
        "begin should differ from end when stdio streams exist"
    );
    assert!(
        !begin.is_null(),
        "begin should not be null with stdio streams"
    );
}

#[test]
fn iter_end_is_constant_sentinel() {
    let end1 = unsafe { _IO_iter_end() };
    let end2 = unsafe { _IO_iter_end() };
    assert_eq!(end1, end2, "end sentinel should be stable");
    assert!(!end1.is_null(), "end sentinel should not be null");
}

#[test]
fn iter_file_returns_valid_native_file() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let begin = unsafe { _IO_iter_begin() };
    let file_ptr = unsafe { _IO_iter_file(begin) };
    assert!(
        !file_ptr.is_null(),
        "iter_file on begin should return non-null FILE*"
    );
}

#[test]
fn iter_file_on_end_returns_null() {
    let end = unsafe { _IO_iter_end() };
    let file_ptr = unsafe { _IO_iter_file(end) };
    assert!(
        file_ptr.is_null(),
        "iter_file on end sentinel should return null"
    );
}

#[test]
fn iter_file_on_null_returns_null() {
    let file_ptr = unsafe { _IO_iter_file(std::ptr::null_mut()) };
    assert!(file_ptr.is_null(), "iter_file on null should return null");
}

#[test]
fn iter_next_advances_past_end() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let end = unsafe { _IO_iter_end() };
    let next = unsafe { _IO_iter_next(end) };
    assert_eq!(next, end, "next on end should return end");
}

#[test]
fn iter_full_traversal_visits_all_streams() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let mut reg = native_stream_registry();
    let initial_count = reg.open_count();

    let mut slots = Vec::new();
    for i in 0..3 {
        let f = NativeFile::new(
            100 + i,
            file_flags::READ | file_flags::WRITE,
            NativeFileBufMode::Full,
        );
        slots.push(reg.register(f).expect("should register"));
    }
    let expected_count = initial_count + 3;
    drop(reg);

    let end = unsafe { _IO_iter_end() };
    let mut it = unsafe { _IO_iter_begin() };
    let mut count = 0;
    while it != end {
        let file_ptr = unsafe { _IO_iter_file(it) };
        assert!(
            !file_ptr.is_null(),
            "iter_file should return non-null for occupied slot"
        );
        count += 1;
        it = unsafe { _IO_iter_next(it) };
        assert!(count <= 300, "infinite loop guard");
    }
    assert_eq!(
        count, expected_count,
        "traversal count should match open_count"
    );

    let mut reg = native_stream_registry();
    for slot in slots {
        reg.unregister(slot);
    }
}

#[test]
fn iter_traversal_after_unregister() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let mut reg = native_stream_registry();

    let f1 = NativeFile::new(200, file_flags::READ, NativeFileBufMode::Full);
    let f2 = NativeFile::new(201, file_flags::READ, NativeFileBufMode::Full);
    let s1 = reg.register(f1).expect("register 1");
    let s2 = reg.register(f2).expect("register 2");
    reg.unregister(s1);
    let expected = reg.open_count();
    drop(reg);

    let end = unsafe { _IO_iter_end() };
    let mut it = unsafe { _IO_iter_begin() };
    let mut count = 0;
    while it != end {
        count += 1;
        it = unsafe { _IO_iter_next(it) };
        assert!(count <= 300, "infinite loop guard");
    }
    assert_eq!(count, expected, "should skip unregistered slot");

    let mut reg = native_stream_registry();
    reg.unregister(s2);
}

// ===========================================================================
// _chain linked list tests (bd-9chy.50)
// ===========================================================================

#[test]
fn chain_stdio_streams_are_linked() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let reg = native_stream_registry();

    // stderr -> stdout -> stdin -> NULL
    let stderr = reg.get(2).expect("stderr");
    let stdout = reg.get(1).expect("stdout");
    let stdin = reg.get(0).expect("stdin");

    // stderr._chain should point to stdout
    let stderr_chain = stderr.chain();
    assert!(!stderr_chain.is_null(), "stderr._chain should not be null");
    // stdout._chain should point to stdin
    let stdout_chain = stdout.chain();
    assert!(!stdout_chain.is_null(), "stdout._chain should not be null");
    // stdin._chain should be null (end of list)
    let stdin_chain = stdin.chain();
    assert!(
        stdin_chain.is_null(),
        "stdin._chain should be null (end of list)"
    );
}

#[test]
fn chain_new_file_becomes_head() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut reg = native_stream_registry();

    // Register a new file - it should become the new head
    let f = NativeFile::new(42, file_flags::READ, NativeFileBufMode::Full);
    let slot = reg.register(f).expect("should register");

    // The new file's chain should NOT be null (it links to something)
    let new_file = reg.get(slot).expect("new file");
    let new_chain = new_file.chain();
    assert!(
        !new_chain.is_null(),
        "new file._chain should not be null after prepend"
    );

    // Verify we can walk the chain without crashing
    let mut count = 0;
    let mut curr = new_file as *const NativeFile as *mut NativeFile;
    while !curr.is_null() {
        count += 1;
        curr = unsafe { (*curr).chain() };
        assert!(count <= 100, "infinite loop guard");
    }
    // Should have at least 4 items: new file + stderr + stdout + stdin
    assert!(
        count >= 4,
        "chain should have at least 4 elements (new + stdio)"
    );

    reg.unregister(slot);
}

#[test]
fn chain_unregister_unlinks_from_list() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut reg = native_stream_registry();

    // Register two files
    let f1 = NativeFile::new(100, file_flags::READ, NativeFileBufMode::Full);
    let f2 = NativeFile::new(101, file_flags::READ, NativeFileBufMode::Full);
    let s1 = reg.register(f1).expect("register f1");
    let s2 = reg.register(f2).expect("register f2");

    // Count chain length starting from f2 (the newest/head)
    let count_before = {
        let f2 = reg.get(s2).expect("f2");
        let mut count = 0;
        let mut curr = f2 as *const NativeFile as *mut NativeFile;
        while !curr.is_null() {
            count += 1;
            curr = unsafe { (*curr).chain() };
            if count > 100 {
                break;
            }
        }
        count
    };

    // Unregister f2 (the head)
    reg.unregister(s2);

    // f1 should still exist and be reachable
    let f1 = reg.get(s1).expect("f1");
    assert_eq!(f1.fd(), 100, "f1 should still exist");

    // Count chain length starting from f1 (now the newest)
    // Should be count_before - 1 (f2 was removed)
    let count_after = {
        let mut count = 0;
        let mut curr = f1 as *const NativeFile as *mut NativeFile;
        while !curr.is_null() {
            count += 1;
            curr = unsafe { (*curr).chain() };
            if count > 100 {
                break;
            }
        }
        count
    };
    assert_eq!(
        count_after,
        count_before - 1,
        "chain should have one fewer element after unregister"
    );

    reg.unregister(s1);
}

#[test]
fn chain_walk_visits_all_streams() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut reg = native_stream_registry();

    // Register 3 additional files
    let mut slots = Vec::new();
    for i in 0..3 {
        let f = NativeFile::new(200 + i, file_flags::READ, NativeFileBufMode::Full);
        slots.push(reg.register(f).expect("register"));
    }

    // Walk the chain manually via _chain pointers starting from newest
    let newest_slot = *slots.last().unwrap();
    let head: *mut NativeFile = reg.get_mut(newest_slot).expect("head") as *mut NativeFile;

    let mut count = 0;
    let mut curr = head;
    while !curr.is_null() {
        count += 1;
        // SAFETY: we're walking NativeFile pointers within the registry
        curr = unsafe { (*curr).chain() };
        assert!(count <= 100, "infinite loop guard");
    }

    // Should have at least: 3 new files + 3 stdio = 6
    assert!(
        count >= 6,
        "chain walk should visit at least 6 streams (3 new + stdio)"
    );

    // Cleanup
    for slot in slots {
        reg.unregister(slot);
    }
}

#[test]
fn chain_io_file_layout_lock_ptr_is_valid() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let reg = native_stream_registry();

    // Access stdout through the _IO_FILE layout
    let stdout = reg.get(1).expect("stdout");
    let file_ptr = (stdout as *const NativeFile).cast::<libc::FILE>();

    // Read the _lock field via the _IO_FILE layout projection
    let projected = unsafe { &*(file_ptr.cast::<IoFilePlusProjection>()) };

    // The _lock pointer should be non-null and valid
    assert!(
        !projected.file._lock.is_null(),
        "_lock pointer should be initialized"
    );

    // The _lock pointer should equal what NativeFile reports
    assert_eq!(
        projected.file._lock,
        stdout.lock_ptr(),
        "_lock via layout should match lock_ptr()"
    );
}
