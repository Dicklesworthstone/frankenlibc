#![cfg(target_os = "linux")]

//! Integration tests for `NativeFile` struct and vtable (bd-zh1y.3.1, bd-zh1y.3.2).

use std::ffi::c_int;

use frankenlibc_abi::io_internal_abi::{
    _IO_iter_begin, _IO_iter_end, _IO_iter_file, _IO_iter_next, DEFAULT_FD_VTABLE,
    NATIVE_FILE_MAGIC, NativeFile, NativeFileBufMode, NativeFileVtable, file_flags,
    native_stream_registry,
};

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
    // Verify the struct has C layout by checking alignment.
    assert!(std::mem::align_of::<NativeFile>() >= 4);
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

#[test]
fn native_file_construct_for_fd() {
    let f = NativeFile::new(3, file_flags::READ, NativeFileBufMode::Full);
    assert!(f.is_valid());
    assert_eq!(f.magic, NATIVE_FILE_MAGIC);
    assert_eq!(f.fd, 3);
    assert!(f.is_readable());
    assert!(!f.is_writable());
    assert!(!f.is_eof());
    assert!(!f.is_error());
    assert_eq!(f.buf_mode, NativeFileBufMode::Full);
    assert!(f.buffer_base.is_null());
    assert_eq!(f.buffer_size, 0);
    assert_eq!(f.offset, 0);
    assert!(f.vtable.is_null());
    assert_eq!(f.lock, 0);
    assert_eq!(f.ungetc_buf, -1);
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
    assert_eq!(f.flags & file_flags::APPEND, file_flags::APPEND);
    assert_eq!(f.buf_mode, NativeFileBufMode::Line);
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
    assert!(f.buffer_base.is_null());
    assert_eq!(f.buffer_size, 0);

    // Simulate assigning a buffer.
    let mut buf = [0u8; 4096];
    f.buffer_base = buf.as_mut_ptr();
    f.buffer_pos = f.buffer_base;
    f.buffer_end = unsafe { f.buffer_base.add(4096) };
    f.buffer_size = 4096;

    assert!(!f.buffer_base.is_null());
    assert_eq!(f.buffer_size, 4096);
    assert_eq!(f.buffer_pos, f.buffer_base);
}

// ---------------------------------------------------------------------------
// Special fd values
// ---------------------------------------------------------------------------

#[test]
fn native_file_closed_fd() {
    let f = NativeFile::new(-1, 0, NativeFileBufMode::None);
    assert!(f.is_valid());
    assert_eq!(f.fd, -1);
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
    assert_eq!(f.fd, -2);
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
    f.magic = 0;
    assert!(!f.is_valid());
}

// ---------------------------------------------------------------------------
// Buffering modes
// ---------------------------------------------------------------------------

#[test]
fn native_file_unbuffered_mode() {
    let f = NativeFile::new(2, file_flags::WRITE, NativeFileBufMode::None);
    assert_eq!(f.buf_mode, NativeFileBufMode::None);
}

#[test]
fn native_file_line_buffered_mode() {
    let f = NativeFile::new(1, file_flags::WRITE, NativeFileBufMode::Line);
    assert_eq!(f.buf_mode, NativeFileBufMode::Line);
}

// ---------------------------------------------------------------------------
// ungetc buffer
// ---------------------------------------------------------------------------

#[test]
fn native_file_ungetc_buf_initially_empty() {
    let f = NativeFile::new(0, file_flags::READ, NativeFileBufMode::Full);
    assert_eq!(f.ungetc_buf, -1); // -1 = empty
}

#[test]
fn native_file_ungetc_buf_stores_byte() {
    let mut f = NativeFile::new(0, file_flags::READ, NativeFileBufMode::Full);
    f.ungetc_buf = b'A' as i16;
    assert_eq!(f.ungetc_buf, 65);
}

// ===========================================================================
// NativeFileVtable tests (bd-zh1y.3.2)
// ===========================================================================

/// Helper: create a temp file fd via memfd_create syscall.
fn temp_memfd() -> c_int {
    let name = b"vtable_test\0";
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) } as c_int;
    assert!(fd >= 0, "memfd_create failed");
    fd
}

#[test]
fn vtable_default_has_all_fields() {
    // Smoke test: DEFAULT_FD_VTABLE is a static with all 5 function pointers.
    let _read = DEFAULT_FD_VTABLE.read;
    let _write = DEFAULT_FD_VTABLE.write;
    let _seek = DEFAULT_FD_VTABLE.seek;
    let _close = DEFAULT_FD_VTABLE.close;
    let _flush = DEFAULT_FD_VTABLE.flush;
}

#[test]
fn vtable_struct_size() {
    // 5 function pointers at 8 bytes each on x86_64.
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

    // Write data.
    let data = b"Hello, vtable!";
    let written = unsafe { (vtable.write)(&mut f, data.as_ptr(), data.len()) };
    assert_eq!(
        written,
        data.len() as isize,
        "write should return bytes written"
    );
    assert_eq!(f.offset, data.len() as i64, "offset should advance");
    assert!(!f.is_error());

    // Seek back to beginning.
    let pos = unsafe { (vtable.seek)(&mut f, 0, libc::SEEK_SET) };
    assert_eq!(pos, 0, "seek to beginning should return 0");
    assert_eq!(f.offset, 0);

    // Read data back.
    let mut buf = [0u8; 64];
    let read = unsafe { (vtable.read)(&mut f, buf.as_mut_ptr(), buf.len()) };
    assert_eq!(read, data.len() as isize, "read should return same bytes");
    assert_eq!(&buf[..data.len()], data);
    assert_eq!(f.offset, data.len() as i64);

    // Close.
    let rc = unsafe { (vtable.close)(&mut f) };
    assert_eq!(rc, 0, "close should succeed");
    assert_eq!(f.fd, -1, "fd should be -1 after close");
}

#[test]
fn vtable_read_eof() {
    let fd = temp_memfd();
    let mut f = NativeFile::new(fd, file_flags::READ, NativeFileBufMode::None);
    let vtable = &DEFAULT_FD_VTABLE;

    // Read from empty memfd => EOF.
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

    // Write some data.
    let data = b"0123456789";
    unsafe { (vtable.write)(&mut f, data.as_ptr(), data.len()) };

    // Seek to end.
    let pos = unsafe { (vtable.seek)(&mut f, 0, libc::SEEK_END) };
    assert_eq!(pos, 10, "SEEK_END should be at byte 10");

    // Seek relative.
    let pos = unsafe { (vtable.seek)(&mut f, -5, libc::SEEK_CUR) };
    assert_eq!(pos, 5, "SEEK_CUR -5 from 10 should be 5");

    unsafe { (vtable.close)(&mut f) };
}

#[test]
fn vtable_seek_clears_eof() {
    let fd = temp_memfd();
    let mut f = NativeFile::new(fd, file_flags::READ, NativeFileBufMode::None);
    let vtable = &DEFAULT_FD_VTABLE;

    // Trigger EOF.
    let mut buf = [0u8; 1];
    unsafe { (vtable.read)(&mut f, buf.as_mut_ptr(), 1) };
    assert!(f.is_eof());

    // Seek clears EOF.
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

    // Set up a buffer and simulate buffered writes.
    let mut buf = [0u8; 128];
    let data = b"buffered data";
    buf[..data.len()].copy_from_slice(data);
    f.buffer_base = buf.as_mut_ptr();
    f.buffer_pos = unsafe { buf.as_mut_ptr().add(data.len()) };
    f.buffer_end = unsafe { buf.as_mut_ptr().add(128) };
    f.buffer_size = 128;

    // Flush should write the buffered data to fd.
    let rc = unsafe { (vtable.flush)(&mut f) };
    assert_eq!(rc, 0, "flush should succeed");
    assert_eq!(
        f.buffer_pos, f.buffer_base,
        "buffer_pos should reset after flush"
    );
    assert!(!f.is_error());

    // Verify data was written by seeking back and reading.
    let seek_pos = unsafe { libc::syscall(libc::SYS_lseek, fd, 0i64, libc::SEEK_SET) };
    assert_eq!(seek_pos, 0);

    let mut read_buf = [0u8; 64];
    let n = unsafe { libc::syscall(libc::SYS_read, fd, read_buf.as_mut_ptr(), 64) };
    assert_eq!(n, data.len() as i64);
    assert_eq!(&read_buf[..data.len()], data);

    // Clean up: close fd (buffer is on the stack and will be dropped with `f`).
    unsafe { libc::syscall(libc::SYS_close, fd) };
    let _ = f;
}

#[test]
fn vtable_close_flushes_before_closing() {
    let fd = temp_memfd();
    let mut f = NativeFile::new(fd, file_flags::WRITE, NativeFileBufMode::Full);
    let vtable = &DEFAULT_FD_VTABLE;

    // Simulate a heap-allocated buffer with pending data.
    let layout = std::alloc::Layout::from_size_align(256, 8).unwrap();
    let heap_buf = unsafe { std::alloc::alloc(layout) };
    assert!(!heap_buf.is_null());

    let data = b"close-flush test";
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), heap_buf, data.len()) };
    f.buffer_base = heap_buf;
    f.buffer_pos = unsafe { heap_buf.add(data.len()) };
    f.buffer_end = unsafe { heap_buf.add(256) };
    f.buffer_size = 256;

    // Dup the fd to verify data after close.
    let verify_fd = unsafe { libc::syscall(libc::SYS_dup, fd) } as c_int;
    assert!(verify_fd >= 0);

    // Close should flush + close fd.
    let rc = unsafe { (vtable.close)(&mut f) };
    assert_eq!(rc, 0);
    assert_eq!(f.fd, -1);

    // Verify data via the dup'd fd.
    unsafe { libc::syscall(libc::SYS_lseek, verify_fd, 0i64, libc::SEEK_SET) };
    let mut read_buf = [0u8; 64];
    let n = unsafe { libc::syscall(libc::SYS_read, verify_fd, read_buf.as_mut_ptr(), 64) };
    assert_eq!(n, data.len() as i64);
    assert_eq!(&read_buf[..data.len()], data);

    unsafe { libc::syscall(libc::SYS_close, verify_fd) };
    // Clean up heap buffer (f no longer owns it since fd is already closed).
    let _ = f;
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
// NativeStreamRegistry tests (bd-zh1y.3.3)
// ===========================================================================

// NOTE: The global registry is shared across all tests in this process.
// Tests that mutate the registry use a static mutex to serialize access.
static REGISTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn registry_pre_registers_stdio() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let reg = native_stream_registry();

    // Slot 0 = stdin (read, fd 0)
    let stdin = reg.get(0).expect("stdin should be pre-registered");
    assert_eq!(stdin.fd, 0);
    assert!(stdin.is_readable());

    // Slot 1 = stdout (write, fd 1)
    let stdout = reg.get(1).expect("stdout should be pre-registered");
    assert_eq!(stdout.fd, 1);
    assert!(stdout.is_writable());

    // Slot 2 = stderr (write, fd 2)
    let stderr = reg.get(2).expect("stderr should be pre-registered");
    assert_eq!(stderr.fd, 2);
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
    assert_eq!(stream.fd, 42);
    assert!(stream.is_valid());

    // Cleanup.
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

    // Double unregister returns false.
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

    // All slots are distinct.
    let unique: std::collections::HashSet<_> = slots.iter().collect();
    assert_eq!(unique.len(), 10);

    // Each stream has the correct fd.
    for (i, &slot) in slots.iter().enumerate() {
        let stream = reg.get(slot).unwrap();
        assert_eq!(stream.fd, 100 + i as i32);
    }

    // Cleanup.
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
        stream.offset = 12345;
    }

    let stream = reg.get(slot).unwrap();
    assert!(stream.is_eof());
    assert_eq!(stream.offset, 12345);

    reg.unregister(slot);
}

#[test]
fn registry_slot_reuse_after_unregister() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let mut reg = native_stream_registry();

    let f1 = NativeFile::new(70, file_flags::READ, NativeFileBufMode::None);
    let slot1 = reg.register(f1).expect("should register");
    reg.unregister(slot1);

    // The freed slot should be reusable.
    let f2 = NativeFile::new(71, file_flags::WRITE, NativeFileBufMode::Line);
    let slot2 = reg.register(f2).expect("should register");
    // Slot2 should be <= slot1 (reuse).
    assert!(slot2 <= slot1, "freed slot should be reused");

    let stream = reg.get(slot2).unwrap();
    assert_eq!(stream.fd, 71);

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

    // Create a memfd-backed writable stream with buffered data.
    let fd = temp_memfd();
    let mut f = NativeFile::new(fd, file_flags::WRITE, NativeFileBufMode::Full);

    // We need a heap buffer that outlives the registry call.
    let layout = std::alloc::Layout::from_size_align(128, 8).unwrap();
    let heap_buf = unsafe { std::alloc::alloc(layout) };
    assert!(!heap_buf.is_null());
    let data = b"flush_all test";
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), heap_buf, data.len()) };
    f.buffer_base = heap_buf;
    f.buffer_pos = unsafe { heap_buf.add(data.len()) };
    f.buffer_end = unsafe { heap_buf.add(128) };
    f.buffer_size = 128;

    let slot = reg.register(f).expect("should register");

    // flush_all should flush our writable stream.
    let errors = reg.flush_all();
    assert_eq!(errors, 0, "flush_all should succeed");

    // Verify data was written to the fd.
    unsafe { libc::syscall(libc::SYS_lseek, fd, 0i64, libc::SEEK_SET) };
    let mut read_buf = [0u8; 64];
    let n = unsafe { libc::syscall(libc::SYS_read, fd, read_buf.as_mut_ptr(), 64) };
    assert_eq!(n, data.len() as i64);
    assert_eq!(&read_buf[..data.len()], data);

    // Cleanup: detach buffer before unregistering.
    if let Some(stream) = reg.get_mut(slot) {
        stream.buffer_base = std::ptr::null_mut();
        stream.buffer_pos = std::ptr::null_mut();
    }
    reg.unregister(slot);
    unsafe { libc::syscall(libc::SYS_close, fd) };
    unsafe { std::alloc::dealloc(heap_buf, layout) };
}

// ===========================================================================
// _IO_iter_* stream iterator tests (bd-di5w)
// ===========================================================================

#[test]
fn iter_begin_returns_first_stream() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    // Registry has stdin/stdout/stderr pre-registered at slots 0/1/2.
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
    // Advancing past end should stay at end.
    let next = unsafe { _IO_iter_next(end) };
    assert_eq!(next, end, "next on end should return end");
}

#[test]
fn iter_full_traversal_visits_all_streams() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let mut reg = native_stream_registry();
    let initial_count = reg.open_count();

    // Register 3 extra streams.
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

    // Iterate and count.
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

    // Cleanup.
    let mut reg = native_stream_registry();
    for slot in slots {
        reg.unregister(slot);
    }
}

#[test]
fn iter_traversal_after_unregister() {
    let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
    let mut reg = native_stream_registry();

    // Register 2 streams, unregister 1.
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
