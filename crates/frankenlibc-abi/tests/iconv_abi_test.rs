#![cfg(target_os = "linux")]

//! Integration tests for `<iconv.h>` ABI entrypoints.
//!
//! Tests cover the full iconv lifecycle: open descriptors, perform character
//! encoding conversions, handle error conditions, and close descriptors.

use std::ffi::{c_char, c_void};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::thread;

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::iconv_abi::{iconv, iconv_close, iconv_open};
use frankenlibc_core::iconv as core_iconv;

const ICONV_ERROR: usize = usize::MAX;

fn c_str(bytes: &[u8]) -> *const c_char {
    bytes.as_ptr().cast::<c_char>()
}

fn iconv_error_handle() -> *mut c_void {
    usize::MAX as *mut c_void
}

// ---------------------------------------------------------------------------
// iconv_open — supported encodings
// ---------------------------------------------------------------------------

#[test]
fn iconv_open_utf8_to_utf16le() {
    let cd = unsafe { iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0")) };
    assert!(!cd.is_null());
    assert_ne!(cd, iconv_error_handle());
    assert_eq!(unsafe { iconv_close(cd) }, 0);
}

#[test]
fn iconv_open_utf8_to_latin1() {
    let cd = unsafe { iconv_open(c_str(b"ISO-8859-1\0"), c_str(b"UTF-8\0")) };
    assert!(!cd.is_null());
    assert_ne!(cd, iconv_error_handle());
    assert_eq!(unsafe { iconv_close(cd) }, 0);
}

#[test]
fn iconv_open_latin1_alias() {
    let cd = unsafe { iconv_open(c_str(b"LATIN1\0"), c_str(b"UTF-8\0")) };
    assert!(!cd.is_null());
    assert_ne!(cd, iconv_error_handle());
    assert_eq!(unsafe { iconv_close(cd) }, 0);
}

#[test]
fn iconv_open_utf8_to_utf32() {
    let cd = unsafe { iconv_open(c_str(b"UTF-32\0"), c_str(b"UTF-8\0")) };
    assert!(!cd.is_null());
    assert_ne!(cd, iconv_error_handle());
    assert_eq!(unsafe { iconv_close(cd) }, 0);
}

#[test]
fn iconv_open_reverse_direction() {
    let cd = unsafe { iconv_open(c_str(b"UTF-8\0"), c_str(b"UTF-16LE\0")) };
    assert!(!cd.is_null());
    assert_ne!(cd, iconv_error_handle());
    assert_eq!(unsafe { iconv_close(cd) }, 0);
}

// ---------------------------------------------------------------------------
// iconv_open — error cases
// ---------------------------------------------------------------------------

#[test]
fn iconv_open_unsupported_encoding_returns_error() {
    let cd = unsafe { iconv_open(c_str(b"EBCDIC\0"), c_str(b"UTF-8\0")) };
    assert_eq!(cd, iconv_error_handle());
}

#[test]
fn iconv_open_null_tocode_returns_error() {
    let cd = unsafe { iconv_open(ptr::null(), c_str(b"UTF-8\0")) };
    assert_eq!(cd, iconv_error_handle());
}

#[test]
fn iconv_open_null_fromcode_returns_error() {
    let cd = unsafe { iconv_open(c_str(b"UTF-8\0"), ptr::null()) };
    assert_eq!(cd, iconv_error_handle());
}

#[test]
fn iconv_open_both_null_returns_error() {
    let cd = unsafe { iconv_open(ptr::null(), ptr::null()) };
    assert_eq!(cd, iconv_error_handle());
}

// ---------------------------------------------------------------------------
// iconv — UTF-8 → UTF-16LE conversion
// ---------------------------------------------------------------------------

#[test]
fn iconv_ascii_to_utf16le() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut input = b"Hello".to_vec();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        let mut output = [0u8; 20];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, 0);
        assert_eq!(in_left, 0, "all input should be consumed");
        assert_eq!(
            out_left, 10,
            "5 chars * 2 bytes = 10 bytes written, 10 remaining"
        );
        // H=0x48, e=0x65, l=0x6C, l=0x6C, o=0x6F in UTF-16LE
        assert_eq!(
            &output[..10],
            &[0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00]
        );

        assert_eq!(iconv_close(cd), 0);
    }
}

#[test]
fn iconv_single_char() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut input = b"X".to_vec();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        let mut output = [0u8; 4];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, 0);
        assert_eq!(in_left, 0);
        assert_eq!(out_left, 2);
        assert_eq!(&output[..2], &[0x58, 0x00]); // 'X' = 0x0058

        assert_eq!(iconv_close(cd), 0);
    }
}

// ---------------------------------------------------------------------------
// iconv — UTF-8 → ISO-8859-1 (Latin-1)
// ---------------------------------------------------------------------------

#[test]
fn iconv_utf8_to_latin1() {
    unsafe {
        let cd = iconv_open(c_str(b"ISO-8859-1\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        // "café" in UTF-8: c=63 a=61 f=66 é=C3 A9
        let mut input = b"caf\xc3\xa9".to_vec();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        let mut output = [0u8; 16];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, 0);
        assert_eq!(in_left, 0);
        // "café" in Latin-1: c=63 a=61 f=66 é=E9
        assert_eq!(&output[..4], &[0x63, 0x61, 0x66, 0xE9]);

        assert_eq!(iconv_close(cd), 0);
    }
}

// ---------------------------------------------------------------------------
// iconv — UTF-8 → UTF-32
// ---------------------------------------------------------------------------

#[test]
fn iconv_utf8_to_utf32() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-32\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut input = b"AB".to_vec();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        let mut output = [0u8; 16];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, 0);
        assert_eq!(in_left, 0);
        // UTF-32 includes a 4-byte BOM + 4 bytes per char = 4 + 2*4 = 12
        let written = 16 - out_left;
        assert!(
            written >= 8,
            "should write at least 8 bytes for 2 chars (got {written})"
        );

        assert_eq!(iconv_close(cd), 0);
    }
}

// ---------------------------------------------------------------------------
// iconv — E2BIG (output buffer too small)
// ---------------------------------------------------------------------------

#[test]
fn iconv_e2big_partial_progress() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut input = b"ABC".to_vec();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        // Only 4 bytes output — room for 2 UTF-16LE chars, not 3
        let mut output = [0u8; 4];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, ICONV_ERROR, "should return error for E2BIG");
        assert_eq!(in_left, 1, "one input byte should remain");
        assert_eq!(out_left, 0, "output buffer should be fully consumed");
        // First two chars converted
        assert_eq!(&output, &[0x41, 0x00, 0x42, 0x00]);

        assert_eq!(iconv_close(cd), 0);
    }
}

// ---------------------------------------------------------------------------
// iconv — reset (null inbuf)
// ---------------------------------------------------------------------------

#[test]
fn iconv_null_inbuf_resets_shift_state() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        // Reset: pass null inbuf
        let rc = iconv(
            cd,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(rc, 0, "reset should succeed with 0");

        assert_eq!(iconv_close(cd), 0);
    }
}

// ---------------------------------------------------------------------------
// iconv — invalid handle
// ---------------------------------------------------------------------------

#[test]
fn iconv_invalid_handle_returns_error() {
    unsafe {
        let fake_cd = 0x12345678usize as *mut c_void;
        let mut input = b"A".to_vec();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();
        let mut output = [0u8; 8];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(
            fake_cd,
            &mut in_ptr,
            &mut in_left,
            &mut out_ptr,
            &mut out_left,
        );
        assert_eq!(rc, ICONV_ERROR);
    }
}

#[test]
fn iconv_null_handle_returns_error() {
    unsafe {
        let mut input = b"A".to_vec();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();
        let mut output = [0u8; 8];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(
            ptr::null_mut(),
            &mut in_ptr,
            &mut in_left,
            &mut out_ptr,
            &mut out_left,
        );
        assert_eq!(rc, ICONV_ERROR);
    }
}

#[test]
fn iconv_input_pointer_without_length_fails() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut input = b"A".to_vec();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut output = [0u8; 8];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(
            cd,
            &mut in_ptr,
            ptr::null_mut(),
            &mut out_ptr,
            &mut out_left,
        );
        assert_eq!(rc, ICONV_ERROR);

        assert_eq!(iconv_close(cd), 0);
    }
}

#[test]
fn iconv_reset_with_output_pointer_but_no_length_fails() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-32\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut output = [0u8; 8];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();

        let rc = iconv(
            cd,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut out_ptr,
            ptr::null_mut(),
        );
        assert_eq!(rc, ICONV_ERROR);

        assert_eq!(iconv_close(cd), 0);
    }
}

#[test]
fn iconv_reset_with_length_but_null_output_pointer_fails() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-32\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut out_ptr: *mut c_char = ptr::null_mut();
        let mut out_left = 8usize;

        let rc = iconv(
            cd,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut out_ptr,
            &mut out_left,
        );
        assert_eq!(rc, ICONV_ERROR);

        assert_eq!(iconv_close(cd), 0);
    }
}

// ---------------------------------------------------------------------------
// iconv_close — error cases
// ---------------------------------------------------------------------------

#[test]
fn iconv_close_null_returns_error() {
    let rc = unsafe { iconv_close(ptr::null_mut()) };
    assert_eq!(rc, -1);
}

#[test]
fn iconv_close_error_handle_returns_error() {
    let rc = unsafe { iconv_close(iconv_error_handle()) };
    assert_eq!(rc, -1);
}

#[test]
fn iconv_close_double_close_returns_error() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());
        assert_eq!(iconv_close(cd), 0);
        // Second close should fail
        let rc = iconv_close(cd);
        assert_eq!(rc, -1, "double close should return -1");
    }
}

#[test]
fn iconv_close_waits_out_concurrent_conversion() {
    let cd = unsafe { iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0")) };
    assert_ne!(cd, iconv_error_handle());

    let cd_addr = cd as usize;
    let attempts = Arc::new(AtomicUsize::new(0));
    let successful_conversions = Arc::new(AtomicUsize::new(0));
    let saw_ebadf = Arc::new(AtomicBool::new(false));
    let unexpected_errno = Arc::new(AtomicI32::new(0));

    let worker_attempts = Arc::clone(&attempts);
    let worker_successful_conversions = Arc::clone(&successful_conversions);
    let worker_saw_ebadf = Arc::clone(&saw_ebadf);
    let worker_unexpected_errno = Arc::clone(&unexpected_errno);
    let worker = thread::spawn(move || {
        for _ in 0..10_000 {
            worker_attempts.fetch_add(1, Ordering::SeqCst);

            let mut input = b"race".to_vec();
            let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
            let mut in_left = input.len();
            let mut output = [0_u8; 16];
            let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
            let mut out_left = output.len();

            let rc = unsafe {
                iconv(
                    cd_addr as *mut c_void,
                    &mut in_ptr,
                    &mut in_left,
                    &mut out_ptr,
                    &mut out_left,
                )
            };
            if rc == ICONV_ERROR {
                let err = unsafe { *__errno_location() };
                if err == libc::EBADF {
                    worker_saw_ebadf.store(true, Ordering::SeqCst);
                    break;
                }
                worker_unexpected_errno.store(err, Ordering::SeqCst);
                break;
            }

            worker_successful_conversions.fetch_add(1, Ordering::SeqCst);
            thread::yield_now();
        }
    });

    while successful_conversions.load(Ordering::SeqCst) == 0
        && attempts.load(Ordering::SeqCst) < 10_000
    {
        thread::yield_now();
    }
    assert!(
        successful_conversions.load(Ordering::SeqCst) > 0,
        "worker should complete at least one conversion before close"
    );

    assert_eq!(unsafe { iconv_close(cd) }, 0);
    assert!(
        worker.join().is_ok(),
        "concurrent iconv worker should not panic"
    );
    assert_eq!(
        unexpected_errno.load(Ordering::SeqCst),
        0,
        "worker should not observe an unexpected iconv errno"
    );

    assert!(
        saw_ebadf.load(Ordering::SeqCst),
        "worker should observe EBADF instead of dereferencing a closed descriptor"
    );
}

// ---------------------------------------------------------------------------
// Round-trip: UTF-8 → UTF-16LE → UTF-8
// ---------------------------------------------------------------------------

#[test]
fn iconv_roundtrip_utf8_utf16le_utf8() {
    unsafe {
        // Forward: UTF-8 → UTF-16LE
        let cd_fwd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd_fwd, iconv_error_handle());

        let original = b"test123";
        let mut input = original.to_vec();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        let mut mid = [0u8; 32];
        let mut out_ptr = mid.as_mut_ptr().cast::<c_char>();
        let mut out_left = mid.len();

        let rc = iconv(
            cd_fwd,
            &mut in_ptr,
            &mut in_left,
            &mut out_ptr,
            &mut out_left,
        );
        assert_eq!(rc, 0);
        let mid_len = 32 - out_left;
        assert_eq!(iconv_close(cd_fwd), 0);

        // Reverse: UTF-16LE → UTF-8
        let cd_rev = iconv_open(c_str(b"UTF-8\0"), c_str(b"UTF-16LE\0"));
        assert_ne!(cd_rev, iconv_error_handle());

        let mut rev_in_ptr = mid.as_mut_ptr().cast::<c_char>();
        let mut rev_in_left = mid_len;
        let mut result = [0u8; 32];
        let mut rev_out_ptr = result.as_mut_ptr().cast::<c_char>();
        let mut rev_out_left = result.len();

        let rc = iconv(
            cd_rev,
            &mut rev_in_ptr,
            &mut rev_in_left,
            &mut rev_out_ptr,
            &mut rev_out_left,
        );
        assert_eq!(rc, 0);
        let result_len = 32 - rev_out_left;
        assert_eq!(&result[..result_len], original);
        assert_eq!(iconv_close(cd_rev), 0);
    }
}

// ---------------------------------------------------------------------------
// Empty input
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// iconv — Latin-1 → UTF-8
// ---------------------------------------------------------------------------

#[test]
fn iconv_latin1_to_utf8() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-8\0"), c_str(b"ISO-8859-1\0"));
        assert_ne!(cd, iconv_error_handle());

        // "café" in Latin-1: c=63 a=61 f=66 é=E9
        let mut input = vec![0x63u8, 0x61, 0x66, 0xE9];
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        let mut output = [0u8; 16];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, 0);
        assert_eq!(in_left, 0);
        // "café" in UTF-8: c=63 a=61 f=66 é=C3 A9
        let written = 16 - out_left;
        assert_eq!(written, 5);
        assert_eq!(&output[..5], b"caf\xc3\xa9");

        assert_eq!(iconv_close(cd), 0);
    }
}

// ---------------------------------------------------------------------------
// iconv — same encoding (passthrough)
// ---------------------------------------------------------------------------

#[test]
fn iconv_open_same_encoding() {
    let cd = unsafe { iconv_open(c_str(b"UTF-8\0"), c_str(b"UTF-8\0")) };
    assert_ne!(cd, iconv_error_handle());
    assert_eq!(unsafe { iconv_close(cd) }, 0);
}

#[test]
fn iconv_utf8_to_utf8_passthrough() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-8\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut input = b"Hello, world!".to_vec();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        let mut output = [0u8; 32];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, 0);
        assert_eq!(in_left, 0);
        let written = 32 - out_left;
        assert_eq!(&output[..written], b"Hello, world!");

        assert_eq!(iconv_close(cd), 0);
    }
}

// ---------------------------------------------------------------------------
// iconv — ASCII subset encoding aliases
// ---------------------------------------------------------------------------

#[test]
fn iconv_open_ascii_alias() {
    let cd = unsafe { iconv_open(c_str(b"ASCII\0"), c_str(b"UTF-8\0")) };
    // ASCII may or may not be supported; just check we don't crash
    if cd != iconv_error_handle() {
        assert_eq!(unsafe { iconv_close(cd) }, 0);
    }
}

// ---------------------------------------------------------------------------
// iconv — multi-byte sequence
// ---------------------------------------------------------------------------

#[test]
fn iconv_utf8_multibyte_to_utf16le() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        // Euro sign: U+20AC = UTF-8: E2 82 AC, UTF-16LE: AC 20
        let mut input = vec![0xE2u8, 0x82, 0xAC];
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        let mut output = [0u8; 8];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, 0);
        assert_eq!(in_left, 0);
        assert_eq!(out_left, 6); // 2 bytes written
        assert_eq!(&output[..2], &[0xAC, 0x20]);

        assert_eq!(iconv_close(cd), 0);
    }
}

// ---------------------------------------------------------------------------
// Empty input
// ---------------------------------------------------------------------------

#[test]
fn iconv_empty_input() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut input = Vec::<u8>::new();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left: usize = 0;

        let mut output = [0u8; 8];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, 0);
        assert_eq!(out_left, 8, "no bytes should be written");

        assert_eq!(iconv_close(cd), 0);
    }
}

#[test]
fn iconv_invalid_utf8_reports_eilseq_and_preserves_progress() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut input = vec![0xC3u8, 0x28];
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let in_start = in_ptr;
        let mut in_left = input.len();

        let mut output = [0u8; 8];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let out_start = out_ptr;
        let mut out_left = output.len();

        *__errno_location() = 0;
        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, ICONV_ERROR);
        assert_eq!(*__errno_location(), core_iconv::ICONV_EILSEQ);
        assert_eq!(in_ptr, in_start, "invalid sequence must not advance input");
        assert_eq!(
            in_left,
            input.len(),
            "invalid sequence must preserve input length"
        );
        assert_eq!(out_ptr, out_start, "invalid sequence must not write output");
        assert_eq!(
            out_left,
            output.len(),
            "invalid sequence must preserve output length"
        );

        assert_eq!(iconv_close(cd), 0);
    }
}

#[test]
fn iconv_incomplete_utf8_reports_einval_and_preserves_progress() {
    unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut input = vec![0xE2u8, 0x82];
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let in_start = in_ptr;
        let mut in_left = input.len();

        let mut output = [0u8; 8];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let out_start = out_ptr;
        let mut out_left = output.len();

        *__errno_location() = 0;
        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, ICONV_ERROR);
        assert_eq!(*__errno_location(), core_iconv::ICONV_EINVAL);
        assert_eq!(
            in_ptr, in_start,
            "truncated multibyte sequence must not advance input"
        );
        assert_eq!(
            in_left,
            input.len(),
            "truncated multibyte sequence must preserve input length"
        );
        assert_eq!(out_ptr, out_start, "truncated input must not write output");
        assert_eq!(
            out_left,
            output.len(),
            "truncated input must preserve output length"
        );

        assert_eq!(iconv_close(cd), 0);
    }
}

// ---------------------------------------------------------------------------
// Strict/Hardened Mode Tests (bd-z7gt)
// ---------------------------------------------------------------------------

use std::sync::Mutex;

/// Mutex for mode env var manipulation (process-global).
static MODE_ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_mode(mode: &str, f: impl FnOnce()) {
    let _guard = MODE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: Serialized by MODE_ENV_LOCK.
    unsafe { std::env::set_var("FRANKENLIBC_MODE", mode) };
    f();
    // SAFETY: Same as above.
    unsafe { std::env::remove_var("FRANKENLIBC_MODE") };
}

#[test]
fn strict_mode_iconv_open_unsupported_returns_error() {
    with_mode("strict", || {
        let cd = unsafe { iconv_open(c_str(b"EBCDIC\0"), c_str(b"UTF-8\0")) };
        assert_eq!(
            cd,
            iconv_error_handle(),
            "strict mode: unsupported encoding should return error"
        );
    });
}

#[test]
fn strict_mode_iconv_open_null_returns_error() {
    with_mode("strict", || {
        let cd = unsafe { iconv_open(ptr::null(), c_str(b"UTF-8\0")) };
        assert_eq!(
            cd,
            iconv_error_handle(),
            "strict mode: null tocode should return error"
        );
    });
}

#[test]
fn strict_mode_iconv_utf8_to_utf16le_succeeds() {
    with_mode("strict", || unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut input = b"Test".to_vec();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        let mut output = [0u8; 16];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, 0, "strict mode: valid conversion should succeed");
        assert_eq!(in_left, 0, "strict mode: all input should be consumed");

        assert_eq!(iconv_close(cd), 0);
    });
}

#[test]
fn hardened_mode_iconv_open_unsupported_returns_error() {
    with_mode("hardened", || {
        let cd = unsafe { iconv_open(c_str(b"EBCDIC\0"), c_str(b"UTF-8\0")) };
        // In hardened mode, unsupported encodings still fail (no healing for invalid codecs).
        assert_eq!(
            cd,
            iconv_error_handle(),
            "hardened mode: unsupported encoding should return error"
        );
    });
}

#[test]
fn hardened_mode_iconv_open_null_returns_error() {
    with_mode("hardened", || {
        let cd = unsafe { iconv_open(ptr::null(), c_str(b"UTF-8\0")) };
        // In hardened mode, null inputs still fail.
        assert_eq!(
            cd,
            iconv_error_handle(),
            "hardened mode: null tocode should return error"
        );
    });
}

#[test]
fn hardened_mode_iconv_utf8_to_utf16le_succeeds() {
    with_mode("hardened", || unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        let mut input = b"Hardened".to_vec();
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        let mut output = [0u8; 32];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, 0, "hardened mode: valid conversion should succeed");
        assert_eq!(in_left, 0, "hardened mode: all input should be consumed");

        assert_eq!(iconv_close(cd), 0);
    });
}

#[test]
fn strict_mode_iconv_invalid_utf8_reports_eilseq() {
    with_mode("strict", || unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        // Invalid UTF-8 sequence
        let mut input = vec![0xC3u8, 0x28];
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        let mut output = [0u8; 8];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        *__errno_location() = 0;
        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        assert_eq!(rc, ICONV_ERROR, "strict mode: invalid UTF-8 should fail");
        assert_eq!(*__errno_location(), core_iconv::ICONV_EILSEQ);

        assert_eq!(iconv_close(cd), 0);
    });
}

#[test]
fn hardened_mode_iconv_invalid_utf8_reports_eilseq() {
    with_mode("hardened", || unsafe {
        let cd = iconv_open(c_str(b"UTF-16LE\0"), c_str(b"UTF-8\0"));
        assert_ne!(cd, iconv_error_handle());

        // Invalid UTF-8 sequence
        let mut input = vec![0xC3u8, 0x28];
        let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
        let mut in_left = input.len();

        let mut output = [0u8; 8];
        let mut out_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut out_left = output.len();

        *__errno_location() = 0;
        let rc = iconv(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left);
        // Hardened mode: invalid sequences still fail (conversion errors aren't healed)
        assert_eq!(rc, ICONV_ERROR, "hardened mode: invalid UTF-8 should fail");
        assert_eq!(*__errno_location(), core_iconv::ICONV_EILSEQ);

        assert_eq!(iconv_close(cd), 0);
    });
}
