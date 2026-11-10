#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc open_wmemstream oracle

//! Live host-glibc comparisons for wide memory storage, wchar_t-unit positions,
//! sparse seeks, overwrite boundaries, publication and saved positions. Wide
//! memory streams do not transcode their values through the process locale.

use frankenlibc_abi::stdio_abi as flio;
use frankenlibc_abi::wchar_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

struct HostStdio {
    open_wmemstream: unsafe extern "C" fn(*mut *mut libc::wchar_t, *mut usize) -> *mut libc::FILE,
    fputws: unsafe extern "C" fn(*const libc::wchar_t, *mut libc::FILE) -> libc::c_int,
    fputwc: unsafe extern "C" fn(libc::wchar_t, *mut libc::FILE) -> u32,
    fseek: unsafe extern "C" fn(*mut libc::FILE, libc::c_long, libc::c_int) -> libc::c_int,
    ftell: unsafe extern "C" fn(*mut libc::FILE) -> libc::c_long,
    fgetpos: unsafe extern "C" fn(*mut libc::FILE, *mut libc::fpos_t) -> libc::c_int,
    fsetpos: unsafe extern "C" fn(*mut libc::FILE, *const libc::fpos_t) -> libc::c_int,
    fwprintf: unsafe extern "C" fn(*mut libc::FILE, *const libc::wchar_t, ...) -> libc::c_int,
    fflush: unsafe extern "C" fn(*mut libc::FILE) -> libc::c_int,
    fclose: unsafe extern "C" fn(*mut libc::FILE) -> libc::c_int,
    flockfile: unsafe extern "C" fn(*mut libc::FILE),
    funlockfile: unsafe extern "C" fn(*mut libc::FILE),
    free: unsafe extern "C" fn(*mut libc::c_void),
}

fn host() -> &'static HostStdio {
    static API: std::sync::LazyLock<HostStdio> = std::sync::LazyLock::new(|| {
        // SAFETY: every function pointer matches its GNU C signature. The
        // explicit library resolver rejects FrankenLibC's own address, so
        // neither the oracle nor its allocator can collapse to the candidate.
        unsafe {
            HostStdio {
                open_wmemstream: dlsym_oracle::host_fn(
                    c"open_wmemstream",
                    fl::open_wmemstream as *const (),
                ),
                fputws: dlsym_oracle::host_fn(c"fputws", fl::fputws as *const ()),
                fputwc: dlsym_oracle::host_fn(c"fputwc", fl::fputwc as *const ()),
                fseek: dlsym_oracle::host_fn(c"fseek", flio::fseek as *const ()),
                ftell: dlsym_oracle::host_fn(c"ftell", flio::ftell as *const ()),
                fgetpos: dlsym_oracle::host_fn(c"fgetpos", flio::fgetpos as *const ()),
                fsetpos: dlsym_oracle::host_fn(c"fsetpos", flio::fsetpos as *const ()),
                fwprintf: dlsym_oracle::host_fn(c"fwprintf", fl::fwprintf as *const ()),
                fflush: dlsym_oracle::host_fn(c"fflush", flio::fflush as *const ()),
                fclose: dlsym_oracle::host_fn(c"fclose", flio::fclose as *const ()),
                flockfile: dlsym_oracle::host_fn(c"flockfile", flio::flockfile as *const ()),
                funlockfile: dlsym_oracle::host_fn(c"funlockfile", flio::funlockfile as *const ()),
                free: dlsym_oracle::host_fn(
                    c"free",
                    frankenlibc_abi::malloc_abi::free as *const (),
                ),
            }
        }
    });
    &API
}

fn wide(s: &str) -> Vec<libc::wchar_t> {
    let mut v: Vec<libc::wchar_t> = s.chars().map(|c| c as libc::wchar_t).collect();
    v.push(0);
    v
}

fn run(glibc: bool) -> Vec<(&'static str, usize, Vec<u32>)> {
    const VIEW: usize = 8;
    let mut ptr: *mut libc::wchar_t = std::ptr::null_mut();
    let mut sz: usize = 999;
    let mut log = Vec::new();

    let stream: *mut libc::FILE = if glibc {
        unsafe { (host().open_wmemstream)(&mut ptr, &mut sz) }
    } else {
        unsafe {
            fl::open_wmemstream(
                &mut ptr as *mut *mut libc::wchar_t as *mut *mut u32,
                &mut sz,
            ) as *mut libc::FILE
        }
    };
    assert!(!stream.is_null(), "open_wmemstream failed (glibc={glibc})");

    let puts = |s: &[libc::wchar_t]| {
        if glibc {
            unsafe { (host().fputws)(s.as_ptr(), stream) };
        } else {
            unsafe { fl::fputws(s.as_ptr(), stream as *mut libc::c_void) };
        }
    };
    let putc = |c: libc::wchar_t| {
        if glibc {
            unsafe { (host().fputwc)(c, stream) };
        } else {
            unsafe { fl::fputwc(c as u32, stream as *mut libc::c_void) };
        }
    };
    let seek = |off: i64| {
        if glibc {
            unsafe { (host().fseek)(stream, off as libc::c_long, libc::SEEK_SET) };
        } else {
            unsafe {
                flio::fseek(
                    stream as *mut libc::c_void,
                    off as libc::c_long,
                    libc::SEEK_SET,
                )
            };
        }
    };
    let flush = || {
        if glibc {
            unsafe { (host().fflush)(stream) };
        } else {
            unsafe { flio::fflush(stream as *mut libc::c_void) };
        }
    };
    // Read only `len` wchars (the buffer is allocated as content_extent+1, so
    // reading the fixed VIEW past a small buffer would be out of bounds).
    let snap = |p: *mut libc::wchar_t, len: usize| -> Vec<u32> {
        if p.is_null() {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(p as *const u32, len.min(VIEW)) }.to_vec()
    };

    let abc = wide("abc");
    puts(&abc[..3]);
    flush();
    log.push(("abc", sz, snap(ptr, 4))); // content extent 3 + NUL
    seek(6);
    putc('X' as i32 as libc::wchar_t);
    flush();
    log.push(("hole+X", sz, snap(ptr, 8))); // extent 7 + NUL
    seek(1);
    putc('Z' as i32 as libc::wchar_t);
    flush();
    log.push(("mid-Z", sz, snap(ptr, 8))); // extent 7 + NUL

    if glibc {
        unsafe { (host().fclose)(stream) };
    } else {
        unsafe { flio::fclose(stream as *mut libc::c_void) };
    }
    log.push(("closed", sz, Vec::new()));
    if glibc {
        unsafe { (host().free)(ptr.cast()) };
    } else {
        unsafe { frankenlibc_abi::malloc_abi::free(ptr.cast()) };
    }
    log
}

#[test]
fn open_wmemstream_sizeloc_matches_glibc() {
    let fl_log = run(false);
    let lc_log = run(true);
    assert_eq!(
        fl_log, lc_log,
        "open_wmemstream diverged from glibc:\n  fl   ={fl_log:x?}\n  glibc={lc_log:x?}"
    );
}

struct Outputs {
    buffer: *mut libc::wchar_t,
    size: usize,
}

struct WideMemory {
    glibc: bool,
    stream: *mut libc::FILE,
    // Output locations must remain stable when the Rust owner moves.
    outputs: Box<Outputs>,
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    position: i64,
    size: usize,
    data: Vec<u32>,
}

impl WideMemory {
    fn new(glibc: bool) -> Self {
        let mut outputs = Box::new(Outputs {
            buffer: std::ptr::null_mut(),
            size: 0,
        });
        let stream = if glibc {
            unsafe { (host().open_wmemstream)(&mut outputs.buffer, &mut outputs.size) }
        } else {
            unsafe {
                fl::open_wmemstream(
                    std::ptr::from_mut(&mut outputs.buffer).cast(),
                    &mut outputs.size,
                )
                .cast()
            }
        };
        assert!(!stream.is_null());
        Self {
            glibc,
            stream,
            outputs,
        }
    }

    fn put(&self, value: u32) -> u32 {
        if self.glibc {
            unsafe { (host().fputwc)(value as libc::wchar_t, self.stream) }
        } else {
            unsafe { fl::fputwc(value, self.stream.cast()) }
        }
    }

    fn puts(&self, values: &[libc::wchar_t]) {
        assert_eq!(values.last(), Some(&0));
        let result = if self.glibc {
            unsafe { (host().fputws)(values.as_ptr(), self.stream) }
        } else {
            unsafe { fl::fputws(values.as_ptr(), self.stream.cast()) }
        };
        assert!(result >= 0);
    }

    fn tell(&self) -> i64 {
        if self.glibc {
            unsafe { (host().ftell)(self.stream) }
        } else {
            unsafe { flio::ftell(self.stream.cast()) }
        }
    }

    fn seek(&self, offset: i64, whence: libc::c_int) -> libc::c_int {
        if self.glibc {
            unsafe { (host().fseek)(self.stream, offset, whence) }
        } else {
            unsafe { flio::fseek(self.stream.cast(), offset, whence) }
        }
    }

    fn save(&self) -> libc::fpos_t {
        let mut position = std::mem::MaybeUninit::zeroed();
        let result = if self.glibc {
            unsafe { (host().fgetpos)(self.stream, position.as_mut_ptr()) }
        } else {
            unsafe { flio::fgetpos(self.stream.cast(), position.as_mut_ptr()) }
        };
        assert_eq!(result, 0);
        unsafe { position.assume_init() }
    }

    fn restore(&self, position: &libc::fpos_t) {
        let result = if self.glibc {
            unsafe { (host().fsetpos)(self.stream, position) }
        } else {
            unsafe { flio::fsetpos(self.stream.cast(), position) }
        };
        assert_eq!(result, 0);
    }

    fn flush(&mut self, visible: usize) -> Snapshot {
        let result = if self.glibc {
            unsafe { (host().fflush)(self.stream) }
        } else {
            unsafe { flio::fflush(self.stream.cast()) }
        };
        assert_eq!(result, 0);
        Snapshot {
            position: self.tell(),
            size: self.outputs.size,
            // Callers pass only the established retained extent + terminator.
            data: unsafe { std::slice::from_raw_parts(self.outputs.buffer.cast::<u32>(), visible) }
                .to_vec(),
        }
    }

    fn finish(&mut self) -> Vec<u32> {
        let result = if self.glibc {
            unsafe { (host().fclose)(self.stream) }
        } else {
            unsafe { flio::fclose(self.stream.cast()) }
        };
        self.stream = std::ptr::null_mut();
        assert_eq!(result, 0);
        unsafe {
            std::slice::from_raw_parts(self.outputs.buffer.cast::<u32>(), self.outputs.size + 1)
        }
        .to_vec()
    }
}

impl Drop for WideMemory {
    fn drop(&mut self) {
        if !self.stream.is_null() {
            let _ = self.finish();
        }
        if self.glibc {
            unsafe { (host().free)(self.outputs.buffer.cast()) };
        } else {
            unsafe { frankenlibc_abi::malloc_abi::free(self.outputs.buffer.cast()) };
        }
    }
}

#[test]
fn wide_positions_overwrites_and_fpos_roundtrip_match_glibc() {
    fn exercise(glibc: bool) -> (Vec<i64>, Vec<Snapshot>, Vec<u32>) {
        let mut file = WideMemory::new(glibc);
        let mut positions = Vec::new();
        for value in [0xe9, 0x3a9, 0x1f600] {
            assert_eq!(file.put(value), value);
            positions.push(file.tell());
        }
        let saved = file.save();
        let mut snapshots = vec![file.flush(4)];
        assert_eq!(file.seek(1, libc::SEEK_SET), 0);
        assert_eq!(file.put(u32::from(b'Z')), u32::from(b'Z'));
        positions.push(file.tell());
        snapshots.push(file.flush(4));
        file.restore(&saved);
        positions.push(file.tell());
        assert_eq!(file.put(0x10348), 0x10348);
        snapshots.push(file.flush(5));
        assert_eq!(file.seek(-2, libc::SEEK_CUR), 0);
        assert_eq!(file.put(0x10ffff), 0x10ffff);
        snapshots.push(file.flush(5));
        assert_eq!(file.seek(-1, libc::SEEK_END), 0);
        positions.push(file.tell());
        (positions, snapshots, file.finish())
    }
    let host = exercise(true);
    assert_eq!(host.0, [1, 2, 3, 2, 3, 2]);
    assert_eq!(host.2, [0xe9, u32::from(b'Z'), 0]);
    assert_eq!(exercise(false), host);
}

#[test]
fn wide_sparse_seeks_and_bulk_writes_match_glibc() {
    fn exercise(glibc: bool) -> (Vec<Snapshot>, Vec<u32>) {
        let mut file = WideMemory::new(glibc);
        assert_eq!(file.put(0xe9), 0xe9);
        let mut snapshots = vec![file.flush(2)];
        let published = (file.outputs.buffer, file.outputs.size);
        assert_eq!(file.seek(6, libc::SEEK_SET), 0);
        assert_eq!((file.outputs.buffer, file.outputs.size), published);
        snapshots.push(file.flush(7));
        let long = "éΩ😀a".repeat(80);
        file.puts(&wide(&long));
        snapshots.push(file.flush(327));
        assert_eq!(file.seek(1, libc::SEEK_SET), 0);
        assert_eq!(file.put(0x1f600), 0x1f600);
        snapshots.push(file.flush(327));
        assert_eq!(file.seek(-1, libc::SEEK_SET), -1);
        assert_eq!(file.tell(), 2);
        (snapshots, file.finish())
    }
    let host = exercise(true);
    assert_eq!(host.0[1].size, 6);
    assert_eq!(host.0[1].data, [0xe9, 0, 0, 0, 0, 0, 0]);
    assert_eq!(host.0[2].position, 326);
    assert_eq!(host.1, [0xe9, 0x1f600, 0]);
    assert_eq!(exercise(false), host);
}

#[test]
fn wide_memory_preserves_all_wchar_bits_without_encoding() {
    fn exercise(glibc: bool) -> Snapshot {
        let mut file = WideMemory::new(glibc);
        for value in [0, 0xd800, 0x110000, 0x7fffffff, 0x80000000, u32::MAX] {
            assert_eq!(file.put(value), value);
        }
        file.puts(&[0xdfff, 0x200000, -2, 0]);
        file.flush(10)
    }
    let host = exercise(true);
    assert_eq!(host.position, 9);
    assert_eq!(host.size, 9);
    assert_eq!(
        host.data,
        [
            0,
            0xd800,
            0x110000,
            0x7fffffff,
            0x80000000,
            u32::MAX,
            0xdfff,
            0x200000,
            u32::MAX - 1,
            0
        ]
    );
    assert_eq!(exercise(false), host);
}

#[test]
fn wide_formatted_output_uses_wchar_positions_and_overwrite_units() {
    fn exercise(glibc: bool) -> (i32, Vec<Snapshot>, Vec<u32>) {
        let mut file = WideMemory::new(glibc);
        let format = wide("[%lc]%ls/%d");
        let text = wide("éΩ😀");
        let result = if glibc {
            unsafe {
                (host().fwprintf)(file.stream, format.as_ptr(), 0x20ac_u32, text.as_ptr(), 23)
            }
        } else {
            unsafe {
                fl::fwprintf(
                    file.stream.cast(),
                    format.as_ptr(),
                    0x20ac_u32,
                    text.as_ptr(),
                    23,
                )
            }
        };
        let mut snapshots = vec![file.flush(10)];
        assert_eq!(file.seek(1, libc::SEEK_SET), 0);
        let format = wide("%ls");
        let text = wide("中");
        let overwritten = if glibc {
            unsafe { (host().fwprintf)(file.stream, format.as_ptr(), text.as_ptr()) }
        } else {
            unsafe { fl::fwprintf(file.stream.cast(), format.as_ptr(), text.as_ptr()) }
        };
        assert_eq!(overwritten, 1);
        snapshots.push(file.flush(10));
        (result, snapshots, file.finish())
    }
    let host = exercise(true);
    assert_eq!(host.0, 9);
    assert_eq!(host.1[0].position, 9);
    assert_eq!(host.2, [u32::from(b'['), 0x4e2d, 0]);
    assert_eq!(exercise(false), host);
}

#[derive(Clone, Copy, Debug)]
enum WideWrite {
    Character,
    String,
    Formatted,
}

fn write_from_thread(
    glibc: bool,
    stream: usize,
    operation: WideWrite,
    text: &[libc::wchar_t],
) -> bool {
    let stream = stream as *mut libc::FILE;
    assert_eq!(text.last(), Some(&0));
    match operation {
        WideWrite::Character => {
            let result = if glibc {
                unsafe { (host().fputwc)(text[0], stream) }
            } else {
                unsafe { fl::fputwc(text[0] as u32, stream.cast()) }
            };
            result == text[0] as u32
        }
        WideWrite::String => {
            let result = if glibc {
                unsafe { (host().fputws)(text.as_ptr(), stream) }
            } else {
                unsafe { fl::fputws(text.as_ptr(), stream.cast()) }
            };
            result >= 0
        }
        WideWrite::Formatted => {
            let format = wide("%ls");
            let result = if glibc {
                unsafe { (host().fwprintf)(stream, format.as_ptr(), text.as_ptr()) }
            } else {
                unsafe { fl::fwprintf(stream.cast(), format.as_ptr(), text.as_ptr()) }
            };
            result == (text.len() - 1) as i32
        }
    }
}

struct HeldWideFileLock {
    glibc: bool,
    stream: *mut libc::FILE,
}

impl HeldWideFileLock {
    fn new(file: &WideMemory) -> Self {
        if file.glibc {
            unsafe { (host().flockfile)(file.stream) };
        } else {
            unsafe { flio::flockfile(file.stream.cast()) };
        }
        Self {
            glibc: file.glibc,
            stream: file.stream,
        }
    }
}

impl Drop for HeldWideFileLock {
    fn drop(&mut self) {
        if self.glibc {
            unsafe { (host().funlockfile)(self.stream) };
        } else {
            unsafe { flio::funlockfile(self.stream.cast()) };
        }
    }
}

#[test]
fn wide_memory_writes_honor_explicit_recursive_file_locks() {
    use std::sync::mpsc::{RecvTimeoutError, channel};
    use std::time::Duration;

    for glibc in [true, false] {
        let file = WideMemory::new(glibc);
        for operation in [
            WideWrite::Character,
            WideWrite::String,
            WideWrite::Formatted,
        ] {
            let lock = HeldWideFileLock::new(&file);
            let text = wide(&"Ω".repeat(600));
            // Same-thread recursion must succeed without taking the cell
            // mutex twice; the worker must wait for the outer FILE unlock.
            assert!(write_from_thread(
                glibc,
                file.stream as usize,
                operation,
                &text
            ));
            let (ready_tx, ready_rx) = channel();
            let (done_tx, done_rx) = channel();
            let address = file.stream as usize;
            let worker = std::thread::spawn(move || {
                ready_tx.send(()).unwrap();
                let result = write_from_thread(glibc, address, operation, &text);
                done_tx.send(result).unwrap();
            });
            let ready = ready_rx.recv_timeout(Duration::from_secs(5));
            let early = done_rx.recv_timeout(Duration::from_millis(100));
            drop(lock);
            // Always release the FILE lock and join before asserting so a
            // failing test cannot close storage still used by the worker.
            let success = match early {
                Ok(success) => success,
                Err(_) => done_rx
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap_or(false),
            };
            let joined = worker.join();
            assert!(ready.is_ok());
            assert!(joined.is_ok());
            assert!(success);
            assert!(
                matches!(early, Err(RecvTimeoutError::Timeout)),
                "{operation:?} bypassed flockfile (glibc={glibc})"
            );
        }
    }
}

#[test]
fn concurrent_wide_strings_and_formatting_keep_each_record_intact() {
    const WRITERS: usize = 4;
    const RECORDS: usize = 16;
    const WIDTH: usize = 2048;
    for glibc in [true, false] {
        let mut file = WideMemory::new(glibc);
        let start = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
        let mut workers = Vec::new();
        for index in 0..WRITERS {
            let start = start.clone();
            let address = file.stream as usize;
            workers.push(std::thread::spawn(move || {
                // Every record crosses eight 256-element staging chunks.
                let mut text = vec![0x3a9 + index as libc::wchar_t; WIDTH];
                text.extend([libc::wchar_t::from(b'\n'), 0]);
                let operation = if index % 2 == 0 {
                    WideWrite::String
                } else {
                    WideWrite::Formatted
                };
                start.wait();
                for _ in 0..RECORDS {
                    if !write_from_thread(glibc, address, operation, &text) {
                        return false;
                    }
                }
                true
            }));
        }
        let results: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
        assert!(results.into_iter().all(|result| matches!(result, Ok(true))));
        let data = file.finish();
        assert_eq!(data.len(), WRITERS * RECORDS * (WIDTH + 1) + 1);
        assert_eq!(data.last(), Some(&0));
        let mut counts = [0; WRITERS];
        for record in data[..data.len() - 1].chunks_exact(WIDTH + 1) {
            assert_eq!(record[WIDTH], u32::from(b'\n'));
            let value = record[0];
            assert!((0x3a9..0x3a9 + WRITERS as u32).contains(&value));
            assert!(
                record[..WIDTH].iter().all(|&wc| wc == value),
                "different operations interleaved wide chunks (glibc={glibc})"
            );
            counts[(value - 0x3a9) as usize] += 1;
        }
        assert_eq!(counts, [RECORDS; WRITERS]);
    }
}
