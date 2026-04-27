#![cfg(target_os = "linux")]

//! Integration tests for nlist(3) over ELF64 binaries.

use std::ffi::{CString, c_char, c_ulong, c_void};
use std::fs;
use std::os::unix::ffi::OsStrExt;

use frankenlibc_abi::malloc_abi;
use frankenlibc_abi::nlist_abi::{CNlist, nlist};

struct MallocCBuffer {
    ptr: *mut c_char,
}

impl MallocCBuffer {
    fn as_ptr(&self) -> *const c_char {
        self.ptr.cast_const()
    }
}

impl Drop for MallocCBuffer {
    fn drop(&mut self) {
        // SAFETY: ptr was allocated by malloc_unterminated and is freed once here.
        unsafe { malloc_abi::free(self.ptr.cast::<c_void>()) };
    }
}

fn malloc_unterminated(bytes: &[u8]) -> MallocCBuffer {
    assert!(!bytes.is_empty());
    assert!(!bytes.contains(&0));
    // SAFETY: allocation size is non-zero and checked for null before use.
    let ptr = unsafe { malloc_abi::malloc(bytes.len()) }.cast::<u8>();
    assert!(!ptr.is_null());
    // SAFETY: ptr points to bytes.len() writable bytes allocated above.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
    MallocCBuffer {
        ptr: ptr.cast::<c_char>(),
    }
}

fn make_entry(name: &CString) -> CNlist {
    CNlist {
        n_name: name.as_ptr(),
        n_type: 0,
        n_other: 0,
        n_desc: 0,
        n_value: 0,
    }
}

fn null_terminator() -> CNlist {
    CNlist {
        n_name: std::ptr::null(),
        n_type: 0,
        n_other: 0,
        n_desc: 0,
        n_value: 0,
    }
}

#[test]
fn nlist_returns_minus_one_on_null_path() {
    let mut nl = [null_terminator()];
    assert_eq!(unsafe { nlist(std::ptr::null(), nl.as_mut_ptr()) }, -1);
}

#[test]
fn nlist_returns_minus_one_on_tracked_unterminated_path() {
    let path = malloc_unterminated(b"/proc/self/exe");
    let mut nl = [null_terminator()];
    assert_eq!(unsafe { nlist(path.as_ptr(), nl.as_mut_ptr()) }, -1);
}

#[test]
fn nlist_returns_minus_one_on_null_array() {
    let path = CString::new("/proc/self/exe").unwrap();
    assert_eq!(unsafe { nlist(path.as_ptr(), std::ptr::null_mut()) }, -1);
}

#[test]
fn nlist_returns_minus_one_on_missing_file() {
    let path = CString::new("/nonexistent/file/for/nlist").unwrap();
    let mut nl = [null_terminator()];
    assert_eq!(unsafe { nlist(path.as_ptr(), nl.as_mut_ptr()) }, -1);
}

#[test]
fn nlist_returns_minus_one_on_non_elf_file() {
    let tmp = std::env::temp_dir().join("nlist_abi_test_non_elf.txt");
    fs::write(&tmp, b"not an ELF binary, just some bytes\n").unwrap();
    let path_bytes = tmp.as_os_str().as_bytes();
    let path = CString::new(path_bytes).unwrap();
    let mut nl = [null_terminator()];
    let rc = unsafe { nlist(path.as_ptr(), nl.as_mut_ptr()) };
    let _ = fs::remove_file(&tmp);
    assert_eq!(rc, -1);
}

#[test]
fn nlist_returns_minus_one_on_empty_file() {
    let tmp = std::env::temp_dir().join("nlist_abi_test_empty.bin");
    fs::write(&tmp, b"").unwrap();
    let path_bytes = tmp.as_os_str().as_bytes();
    let path = CString::new(path_bytes).unwrap();
    let mut nl = [null_terminator()];
    let rc = unsafe { nlist(path.as_ptr(), nl.as_mut_ptr()) };
    let _ = fs::remove_file(&tmp);
    assert_eq!(rc, -1);
}

#[test]
fn nlist_returns_zero_for_empty_request_on_real_binary() {
    let path = CString::new("/proc/self/exe").unwrap();
    let mut nl = [null_terminator()];
    let rc = unsafe { nlist(path.as_ptr(), nl.as_mut_ptr()) };
    // The test binary is a real ELF64; an empty request should
    // succeed with 0 unfound symbols.
    assert_eq!(rc, 0);
}

#[test]
fn nlist_finds_main_symbol_in_test_binary() {
    let path = CString::new("/proc/self/exe").unwrap();
    let main_name = CString::new("main").unwrap();
    let bogus_name = CString::new("definitely_not_a_real_symbol_xyz_12345").unwrap();

    let mut nl = vec![
        make_entry(&main_name),
        make_entry(&bogus_name),
        null_terminator(),
    ];

    let rc = unsafe { nlist(path.as_ptr(), nl.as_mut_ptr()) };
    // The test binary must have a `main` symbol (Rust test runner
    // entry). The bogus symbol must not exist.
    assert!(
        rc >= 0,
        "nlist must succeed on a real ELF64 test binary (got {rc})"
    );
    assert_eq!(rc, 1, "exactly one unfound symbol expected");

    // main found: n_value non-zero, n_type non-zero (function bind).
    assert!(
        nl[0].n_value != 0 as c_ulong,
        "main symbol should have a non-zero address"
    );
    assert_ne!(nl[0].n_type, 0, "main symbol should have non-zero st_info");

    // bogus not found: all-zero output fields.
    assert_eq!(nl[1].n_value, 0 as c_ulong);
    assert_eq!(nl[1].n_type, 0);
    assert_eq!(nl[1].n_desc, 0);
}

#[test]
fn nlist_returns_minus_one_on_tracked_unterminated_symbol_name() {
    let path = CString::new("/proc/self/exe").unwrap();
    let bad_name = malloc_unterminated(b"main");
    let mut nl = [
        CNlist {
            n_name: bad_name.as_ptr(),
            n_type: 77,
            n_other: 66,
            n_desc: 55,
            n_value: 44,
        },
        null_terminator(),
    ];

    let rc = unsafe { nlist(path.as_ptr(), nl.as_mut_ptr()) };
    assert_eq!(rc, -1);
    assert_eq!(nl[0].n_type, 77);
    assert_eq!(nl[0].n_value, 44);
}

#[test]
fn nlist_handles_empty_string_name_terminator() {
    let path = CString::new("/proc/self/exe").unwrap();
    let empty_name = CString::new("").unwrap();
    // Use the empty-string sentinel form of the array terminator
    // (n_name points to a "", not NULL): nlist must still return 0
    // unfound for an effectively-empty request list.
    let mut nl = [CNlist {
        n_name: empty_name.as_ptr(),
        n_type: 99,
        n_other: 99,
        n_desc: 99,
        n_value: 99,
    }];
    let rc = unsafe { nlist(path.as_ptr(), nl.as_mut_ptr()) };
    assert_eq!(rc, 0);
    // The terminator entry's fields should be left untouched (we
    // never write through to it).
    assert_eq!(nl[0].n_type, 99);
    assert_eq!(nl[0].n_value, 99);
}
