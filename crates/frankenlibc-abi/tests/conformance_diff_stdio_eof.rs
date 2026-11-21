#![cfg(all(target_os = "linux", not(feature = "standalone")))]
#![allow(unsafe_code)] // Real FILE operations, compared with separately resolved glibc.

//! fread's sticky EOF applies to buffer underflow, while GNU's direct-read
//! path can read newly appended bytes with the old EOF indicator still set.
//! Run this target in both strict and hardened modes.

use std::ffi::{CString, c_char, c_int, c_void};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::stdio_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

struct StdioArm {
    name: &'static str,
    fopen: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void,
    fclose: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    setvbuf: unsafe extern "C-unwind" fn(*mut c_void, *mut c_char, c_int, usize) -> c_int,
    fread: unsafe extern "C-unwind" fn(*mut c_void, usize, usize, *mut c_void) -> usize,
    feof: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    ferror: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    clearerr: unsafe extern "C-unwind" fn(*mut c_void),
}

fn candidate() -> StdioArm {
    StdioArm {
        name: "fl",
        fopen: fl::fopen,
        fclose: fl::fclose,
        setvbuf: fl::setvbuf,
        fread: fl::fread,
        feof: fl::feof,
        ferror: fl::ferror,
        clearerr: fl::clearerr,
    }
}

fn host() -> StdioArm {
    // SAFETY: each function type matches its named ABI. The resolver verifies
    // that no oracle pointer binds back to the candidate implementation.
    unsafe {
        StdioArm {
            name: "glibc",
            fopen: dlsym_oracle::host_fn(c"fopen", fl::fopen as *const ()),
            fclose: dlsym_oracle::host_fn(c"fclose", fl::fclose as *const ()),
            setvbuf: dlsym_oracle::host_fn(c"setvbuf", fl::setvbuf as *const ()),
            fread: dlsym_oracle::host_fn(c"fread", fl::fread as *const ()),
            feof: dlsym_oracle::host_fn(c"feof", fl::feof as *const ()),
            ferror: dlsym_oracle::host_fn(c"ferror", fl::ferror as *const ()),
            clearerr: dlsym_oracle::host_fn(c"clearerr", fl::clearerr as *const ()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ReadAfterEof {
    count: usize,
    first_byte: u8,
    eof: bool,
    error: bool,
    eof_after_clear: bool,
    retry_count: usize,
    retry_first_byte: u8,
    retry_eof: bool,
    retry_error: bool,
}

fn observe(arm: &StdioArm, mode: c_int, request: usize) -> ReadAfterEof {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "fl-stdio-eof-{}-{}-{}",
        std::process::id(),
        arm.name,
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, b"x").unwrap();
    let c_path = CString::new(path.to_str().unwrap()).unwrap();
    let mut storage = [0u8; 64];
    let mut bytes = [0xa5u8; 128];
    // SAFETY: the regular file and caller-owned stdio buffer remain live until
    // fclose; every read fits bytes and every operation uses the same provider.
    unsafe {
        let stream = (arm.fopen)(c_path.as_ptr(), c"r".as_ptr());
        assert!(!stream.is_null(), "{}: fopen", arm.name);
        if arm.name == "fl" {
            assert!(!fl::stdio_may_delegate_to_host_for_tests(stream));
        }
        assert_eq!(
            (arm.setvbuf)(stream, storage.as_mut_ptr().cast(), mode, storage.len()),
            0
        );
        assert_eq!((arm.fread)(bytes.as_mut_ptr().cast(), 1, 1, stream), 1);
        assert_eq!(bytes[0], b'x');
        assert_eq!((arm.fread)(bytes.as_mut_ptr().cast(), 1, 1, stream), 0);
        assert_ne!((arm.feof)(stream), 0);
        assert_eq!((arm.ferror)(stream), 0);

        // A separate descriptor extends the file without changing this FILE's
        // cursor, buffer or EOF flag. The next read must choose its real path.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"y")
            .unwrap();
        bytes.fill(0xa5);
        let count = (arm.fread)(bytes.as_mut_ptr().cast(), 1, request, stream);
        let first_byte = bytes[0];
        assert!(bytes[1..].iter().all(|&byte| byte == 0xa5));
        let eof = (arm.feof)(stream) != 0;
        let error = (arm.ferror)(stream) != 0;
        (arm.clearerr)(stream);
        let eof_after_clear = (arm.feof)(stream) != 0;
        bytes[0] = 0xa5;
        let retry_count = (arm.fread)(bytes.as_mut_ptr().cast(), 1, 1, stream);
        let result = ReadAfterEof {
            count,
            first_byte,
            eof,
            error,
            eof_after_clear,
            retry_count,
            retry_first_byte: bytes[0],
            retry_eof: (arm.feof)(stream) != 0,
            retry_error: (arm.ferror)(stream) != 0,
        };
        assert_eq!((arm.fclose)(stream), 0);
        result
    }
}

fn compare(mode: c_int, request: usize, direct: bool) {
    let oracle = observe(&host(), mode, request);
    assert_eq!(
        oracle,
        ReadAfterEof {
            count: usize::from(direct),
            first_byte: if direct { b'y' } else { 0xa5 },
            eof: true,
            error: false,
            eof_after_clear: false,
            retry_count: usize::from(!direct),
            retry_first_byte: if direct { 0xa5 } else { b'y' },
            retry_eof: direct,
            retry_error: false,
        },
        "GNU oracle mode={mode} request={request}"
    );
    assert_eq!(
        observe(&candidate(), mode, request),
        oracle,
        "fread after file growth: mode={mode} request={request}"
    );
}

#[test]
fn fread_small_request_keeps_eof_until_clearerr() {
    compare(libc::_IOFBF, 1, false);
}

#[test]
fn fread_direct_requests_preserve_gnu_eof_bypass() {
    // Exact buffer capacity and larger reads both bypass underflow.
    for request in [64, 128] {
        compare(libc::_IOFBF, request, true);
    }
}

#[test]
fn fread_unbuffered_request_preserves_gnu_eof_bypass() {
    compare(libc::_IONBF, 1, true);
}
