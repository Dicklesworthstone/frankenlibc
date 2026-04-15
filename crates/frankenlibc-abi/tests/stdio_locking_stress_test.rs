//! Stress test for stdio locking (bd-9chy.17)
//!
//! Verifies that flockfile/funlockfile/ftrylockfile work correctly under
//! concurrent access, ensuring no torn writes occur.

#![cfg(target_os = "linux")]

use std::ffi::{CString, c_char, c_int, c_void};
use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

// Import the ABI functions
unsafe extern "C" {
    fn fopen(pathname: *const c_char, mode: *const c_char) -> *mut c_void;
    fn fclose(stream: *mut c_void) -> c_int;
    fn fwrite(ptr: *const c_void, size: usize, nmemb: usize, stream: *mut c_void) -> usize;
    fn fread(ptr: *mut c_void, size: usize, nmemb: usize, stream: *mut c_void) -> usize;
    fn flockfile(stream: *mut c_void);
    fn funlockfile(stream: *mut c_void);
    fn ftrylockfile(stream: *mut c_void) -> c_int;
    fn fflush(stream: *mut c_void) -> c_int;
}

/// A wrapper to make FILE* Send+Sync for testing purposes.
/// The locking functions are responsible for thread safety.
struct SharedFile(*mut c_void);
unsafe impl Send for SharedFile {}
unsafe impl Sync for SharedFile {}

impl SharedFile {
    fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("frl_stress_{}_{}", name, ts))
}

/// Test that 32 threads can write 4-byte records concurrently without torn writes.
///
/// Each thread writes 1024 records of format [thread_id: u8, seq_lo: u8, seq_hi: u8, check: u8]
/// where check = thread_id ^ seq_lo ^ seq_hi.
///
/// If locking works correctly, no record should have mismatched check bytes.
#[test]
fn stress_32_threads_1024_records_each() {
    const NUM_THREADS: usize = 32;
    const RECORDS_PER_THREAD: usize = 1024;
    const RECORD_SIZE: usize = 4;

    let path = temp_path("stress32");
    let path_c = CString::new(path.to_str().unwrap()).unwrap();

    // Create file for writing
    let file = unsafe { fopen(path_c.as_ptr(), c"w".as_ptr()) };
    assert!(!file.is_null(), "Failed to open file for writing");

    let shared_file = Arc::new(SharedFile(file));
    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|tid| {
            let file = Arc::clone(&shared_file);
            let barrier = Arc::clone(&barrier);

            thread::spawn(move || {
                // Wait for all threads to be ready
                barrier.wait();

                for seq in 0..RECORDS_PER_THREAD {
                    let record: [u8; RECORD_SIZE] = [
                        tid as u8,
                        (seq & 0xFF) as u8,
                        ((seq >> 8) & 0xFF) as u8,
                        (tid as u8) ^ ((seq & 0xFF) as u8) ^ (((seq >> 8) & 0xFF) as u8),
                    ];

                    unsafe {
                        flockfile(file.as_ptr());
                        let written = fwrite(record.as_ptr().cast(), RECORD_SIZE, 1, file.as_ptr());
                        funlockfile(file.as_ptr());
                        assert_eq!(written, 1, "Write failed for thread {} seq {}", tid, seq);
                    }
                }
            })
        })
        .collect();

    // Wait for all threads to complete
    for h in handles {
        h.join().expect("Thread panicked");
    }

    // Flush and close
    unsafe {
        fflush(shared_file.as_ptr());
        fclose(shared_file.as_ptr());
    }

    // Reopen and verify
    let file = unsafe { fopen(path_c.as_ptr(), c"r".as_ptr()) };
    assert!(!file.is_null(), "Failed to open file for reading");

    let expected_records = NUM_THREADS * RECORDS_PER_THREAD;
    let mut records_read = 0;
    let mut torn_writes = 0;
    let mut thread_counts = vec![0usize; NUM_THREADS];

    loop {
        let mut record = [0u8; RECORD_SIZE];
        let read = unsafe { fread(record.as_mut_ptr().cast(), RECORD_SIZE, 1, file) };

        if read == 0 {
            break;
        }

        records_read += 1;

        let tid = record[0] as usize;
        let seq_lo = record[1];
        let seq_hi = record[2];
        let check = record[3];

        let expected_check = record[0] ^ seq_lo ^ seq_hi;

        if check != expected_check {
            torn_writes += 1;
        }

        if tid < NUM_THREADS {
            thread_counts[tid] += 1;
        }
    }

    unsafe { fclose(file) };
    let _ = fs::remove_file(&path);

    // Assertions
    assert_eq!(
        records_read, expected_records,
        "Expected {} records, read {}",
        expected_records, records_read
    );
    assert_eq!(
        torn_writes, 0,
        "Found {} torn writes - locking is broken!",
        torn_writes
    );

    // Verify each thread wrote the expected number of records
    for (tid, &count) in thread_counts.iter().enumerate() {
        assert_eq!(
            count, RECORDS_PER_THREAD,
            "Thread {} wrote {} records instead of {}",
            tid, count, RECORDS_PER_THREAD
        );
    }
}

/// Test ftrylockfile returns 0 when lock is available, -1 when held.
#[test]
fn ftrylockfile_returns_correct_values() {
    let path = temp_path("trylock");
    let path_c = CString::new(path.to_str().unwrap()).unwrap();

    let file = unsafe { fopen(path_c.as_ptr(), c"w".as_ptr()) };
    assert!(!file.is_null());

    // First trylock should succeed
    let rc1 = unsafe { ftrylockfile(file) };
    assert_eq!(rc1, 0, "First ftrylockfile should return 0");

    // Second trylock should also succeed (recursive lock)
    let rc2 = unsafe { ftrylockfile(file) };
    assert_eq!(rc2, 0, "Recursive ftrylockfile should return 0");

    // Unlock both
    unsafe { funlockfile(file) };
    unsafe { funlockfile(file) };

    unsafe { fclose(file) };
    let _ = fs::remove_file(&path);
}

/// Test flockfile/funlockfile with nested calls (recursive locking).
#[test]
fn nested_flockfile_does_not_deadlock() {
    let path = temp_path("nested");
    let path_c = CString::new(path.to_str().unwrap()).unwrap();

    let file = unsafe { fopen(path_c.as_ptr(), c"w".as_ptr()) };
    assert!(!file.is_null());

    // Nested locks should not deadlock
    unsafe {
        flockfile(file);
        flockfile(file);
        flockfile(file);
        funlockfile(file);
        funlockfile(file);
        funlockfile(file);
    }

    unsafe { fclose(file) };
    let _ = fs::remove_file(&path);
}

/// Test that writes are atomic at the record level when using flockfile.
#[test]
fn writes_are_record_atomic_with_locking() {
    const NUM_THREADS: usize = 8;
    const ITERATIONS: usize = 100;
    const RECORD_SIZE: usize = 16;

    let path = temp_path("atomic");
    let path_c = CString::new(path.to_str().unwrap()).unwrap();

    let file = unsafe { fopen(path_c.as_ptr(), c"w".as_ptr()) };
    assert!(!file.is_null());

    let shared_file = Arc::new(SharedFile(file));
    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|tid| {
            let file = Arc::clone(&shared_file);
            let barrier = Arc::clone(&barrier);

            thread::spawn(move || {
                barrier.wait();

                for _ in 0..ITERATIONS {
                    // Create a record filled with the thread ID
                    let record = [tid as u8; RECORD_SIZE];

                    unsafe {
                        flockfile(file.as_ptr());
                        fwrite(record.as_ptr().cast(), RECORD_SIZE, 1, file.as_ptr());
                        funlockfile(file.as_ptr());
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("Thread panicked");
    }

    unsafe {
        fflush(shared_file.as_ptr());
        fclose(shared_file.as_ptr());
    }

    // Verify: each record should contain all the same byte
    let file = unsafe { fopen(path_c.as_ptr(), c"r".as_ptr()) };
    assert!(!file.is_null());

    let mut torn = 0;
    loop {
        let mut record = [0u8; RECORD_SIZE];
        let read = unsafe { fread(record.as_mut_ptr().cast(), RECORD_SIZE, 1, file) };
        if read == 0 {
            break;
        }

        let first = record[0];
        if !record.iter().all(|&b| b == first) {
            torn += 1;
        }
    }

    unsafe { fclose(file) };
    let _ = fs::remove_file(&path);

    assert_eq!(torn, 0, "Found {} torn records", torn);
}
