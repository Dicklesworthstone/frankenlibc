#![cfg(target_os = "linux")]

//! Integration tests for `<wchar.h>` ABI entrypoints.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::{Mutex, MutexGuard};

use frankenlibc_abi::glibc_internal_abi::fwide;
use frankenlibc_abi::io_internal_abi::verify_native_file;
use frankenlibc_abi::malloc_abi::{free, malloc};
use frankenlibc_abi::stdlib_abi::{basename, dirname, realpath};
use frankenlibc_abi::wchar_abi::*;

/// Acquire poison-tolerantly, so a failing assertion reports as one failure instead of
/// poisoning this guard and taking every later test with it (bd-9ri7g1).
static STDIO_GLOBAL_STREAM_LOCK: Mutex<()> = Mutex::new(());

fn run_native_wchar_test_in_child(name: &str) -> bool {
    const CHILD: &str = "FRANKENLIBC_NATIVE_WCHAR_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    // Native admission permanently disables shared compiler-TLS caches. Keep
    // every regression's first-clone transition out of other test processes.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start native wchar child");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut timed_out = false;
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !timed_out && output.status.success() && stdout.contains("1 passed;"),
        "native wchar child timeout={timed_out} status={}\n{stdout}\n{stderr}",
        output.status
    );
    true
}

fn run_native_wchar_worker(
    worker: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    argument: *mut c_void,
) -> usize {
    struct RestoreBackend(bool);
    impl Drop for RestoreBackend {
        fn drop(&mut self) {
            frankenlibc_abi::pthread_abi::pthread_threading_restore_for_tests(self.0);
        }
    }
    let _restore = RestoreBackend(
        frankenlibc_abi::pthread_abi::pthread_threading_swap_force_native_for_tests(),
    );
    let mut thread = 0;
    // SAFETY: the caller keeps all callback arguments alive through join.
    assert_eq!(
        unsafe {
            frankenlibc_abi::pthread_abi::pthread_create(
                &mut thread,
                std::ptr::null(),
                Some(worker),
                argument,
            )
        },
        0
    );
    let mut result = std::ptr::null_mut();
    // SAFETY: this is the live joinable native thread returned above.
    assert_eq!(
        unsafe { frankenlibc_abi::pthread_abi::pthread_join(thread, &mut result) },
        0
    );
    result as usize
}

#[test]
#[cfg(debug_assertions)]
fn wchar_native_tls_formatting_avoids_the_creators_borrowed_pool() {
    if run_native_wchar_test_in_child(
        "wchar_native_tls_formatting_avoids_the_creators_borrowed_pool",
    ) {
        return;
    }
    unsafe extern "C" fn format(_: *mut c_void) -> *mut c_void {
        let long = [b'[' as i32, b'%' as i32, b'd' as i32, b']' as i32, 0];
        let short = [b'%' as i32, b'd' as i32, 0];
        let mut out = [0_i32; 16];
        // SAFETY: terminated wide formats, matching promoted arguments, and a
        // writable output buffer. Report scalar failures without unwinding.
        unsafe {
            if swprintf(out.as_mut_ptr(), out.len(), long.as_ptr(), 42 as c_int) != 4
                || out[..5] != [b'[' as i32, b'4' as i32, b'2' as i32, b']' as i32, 0]
            {
                return 1usize as *mut c_void;
            }
            if swprintf(out.as_mut_ptr(), out.len(), short.as_ptr(), 7 as c_int) != 1
                || out[..2] != [b'7' as i32, 0]
            {
                return 2usize as *mut c_void;
            }
        }
        std::ptr::null_mut()
    }
    let result = with_wchar_format_pool_borrow_for_tests(|| {
        run_native_wchar_worker(format, std::ptr::null_mut())
    });
    assert_eq!(result, 0);
}

#[test]
fn wchar_native_tls_preserves_the_creators_returned_wide_line() {
    if run_native_wchar_test_in_child("wchar_native_tls_preserves_the_creators_returned_wide_line")
    {
        return;
    }
    unsafe extern "C" fn read_line(stream: *mut c_void) -> *mut c_void {
        let mut length = 0;
        // SAFETY: the creator keeps this independent FILE alive until join.
        let line = unsafe { fgetwln(stream, &mut length) };
        if line.is_null() || length != 6 {
            return 1usize as *mut c_void;
        }
        let expected = [
            b'c' as i32,
            b'h' as i32,
            b'i' as i32,
            b'l' as i32,
            b'd' as i32,
            10,
        ];
        // SAFETY: the returned buffer has exactly length readable wide chars.
        if unsafe { std::slice::from_raw_parts(line, length) } != expected.as_slice() {
            return 2usize as *mut c_void;
        }
        std::ptr::null_mut()
    }
    let creator_line = wstr(b"creator-wide\n");
    let child_line = wstr(b"child\n");
    // SAFETY: both FILEs and terminated wide strings outlive native execution.
    unsafe {
        let creator = frankenlibc_abi::stdio_abi::tmpfile();
        let child = frankenlibc_abi::stdio_abi::tmpfile();
        assert!(!creator.is_null() && !child.is_null());
        assert!(verify_native_file(creator).is_some());
        assert!(verify_native_file(child).is_some());
        assert_eq!(fputws(creator_line.as_ptr().cast(), creator), 0);
        assert_eq!(fputws(child_line.as_ptr().cast(), child), 0);
        assert_eq!(
            frankenlibc_abi::stdio_abi::fseek(creator, 0, libc::SEEK_SET),
            0
        );
        assert_eq!(
            frankenlibc_abi::stdio_abi::fseek(child, 0, libc::SEEK_SET),
            0
        );
        let mut length = 0;
        let retained = fgetwln(creator, &mut length);
        assert!(!retained.is_null());
        assert_eq!(length, creator_line.len() - 1);

        assert_eq!(run_native_wchar_worker(read_line, child), 0);
        assert_eq!(
            std::slice::from_raw_parts(retained.cast::<u32>(), length),
            &creator_line[..creator_line.len() - 1]
        );
        assert_eq!(
            frankenlibc_abi::stdio_abi::fseek(creator, 0, libc::SEEK_SET),
            0
        );
        let next = fgetwln(creator, &mut length);
        assert!(!next.is_null());
        assert_eq!(
            std::slice::from_raw_parts(next.cast::<u32>(), length),
            &creator_line[..creator_line.len() - 1]
        );
        assert_eq!(frankenlibc_abi::stdio_abi::fclose(creator), 0);
        assert_eq!(frankenlibc_abi::stdio_abi::fclose(child), 0);
    }
}

#[test]
fn wchar_native_tls_keeps_pending_utf8_and_utf16_state_per_thread() {
    if run_native_wchar_test_in_child(
        "wchar_native_tls_keeps_pending_utf8_and_utf16_state_per_thread",
    ) {
        return;
    }
    unsafe extern "C" fn convert(_: *mut c_void) -> *mut c_void {
        let mut wide: libc::wchar_t = 0;
        let mut unit = 0_u16;
        let mut bytes = [0_u8; 4];
        let mut failures = 0usize;
        // SAFETY: all input/output arrays are live; null ps deliberately tests
        // the three separate implicit conversion states, without assertions.
        unsafe {
            if mbrtowc(&mut wide, c"A".as_ptr(), 1, std::ptr::null_mut()) != 1
                || wide != b'A' as i32
            {
                failures |= 1;
            }
            if mbrtoc16(&mut unit, c"B".as_ptr(), 1, std::ptr::null_mut()) != 1
                || unit != b'B' as u16
            {
                failures |= 2;
            }
            if c16rtomb(bytes.as_mut_ptr().cast(), b'C' as u16, std::ptr::null_mut()) != 1
                || bytes[0] != b'C'
            {
                failures |= 4;
            }
            if mbrtowc(
                &mut wide,
                [0xe2_u8].as_ptr().cast(),
                1,
                std::ptr::null_mut(),
            ) != usize::MAX - 1
                || mbrtowc(
                    &mut wide,
                    [0x82_u8, 0xac].as_ptr().cast(),
                    2,
                    std::ptr::null_mut(),
                ) != 2
                || wide != 0x20ac
            {
                failures |= 8;
            }
        }
        failures as *mut c_void
    }
    // Use a global UTF-8 locale in this isolated process. This regression does
    // not rely on the separately unfinished native uselocale implementation.
    // SAFETY: all input arrays are live for their calls and the local output
    // objects have the complete wchar/char16/four-byte extents required below.
    unsafe {
        assert!(
            !frankenlibc_abi::locale_abi::setlocale(libc::LC_CTYPE, c"C.UTF-8".as_ptr()).is_null()
        );
        let mut wide: libc::wchar_t = 0;
        let mut unit = 0_u16;
        let mut bytes = [0_u8; 4];
        assert_eq!(
            mbrtowc(
                &mut wide,
                [0xe2_u8].as_ptr().cast(),
                1,
                std::ptr::null_mut()
            ),
            usize::MAX - 1
        );
        assert_eq!(
            mbrtoc16(
                &mut unit,
                [0xf0_u8, 0x9f, 0x98, 0x80].as_ptr().cast(),
                4,
                std::ptr::null_mut(),
            ),
            4
        );
        assert_eq!(unit, 0xd83d);
        assert_eq!(
            c16rtomb(bytes.as_mut_ptr().cast(), 0xd83d, std::ptr::null_mut()),
            0
        );

        assert_eq!(run_native_wchar_worker(convert, std::ptr::null_mut()), 0);
        assert_eq!(
            mbrtowc(
                &mut wide,
                [0x82_u8, 0xac].as_ptr().cast(),
                2,
                std::ptr::null_mut(),
            ),
            2
        );
        assert_eq!(wide, 0x20ac);
        assert_eq!(
            mbrtoc16(&mut unit, c"".as_ptr(), 0, std::ptr::null_mut()),
            usize::MAX - 2
        );
        assert_eq!(unit, 0xde00);
        assert_eq!(
            c16rtomb(bytes.as_mut_ptr().cast(), 0xde00, std::ptr::null_mut()),
            4
        );
        assert_eq!(bytes, [0xf0, 0x9f, 0x98, 0x80]);
    }
}

#[test]
fn swprintf_unknown_conversions_keep_following_arguments_and_count() {
    let fmt: Vec<libc::wchar_t> = "%*.*lQ:%d:%s:%.1f%n\0".chars().map(|c| c as i32).collect();
    let mut buf = [0x5a_i32; 64];
    let mut count = -77_i32;
    // SAFETY: format and string are terminated, operand types match, and
    // both the wchar buffer and count pointer are live writable objects.
    let written = unsafe {
        swprintf(
            buf.as_mut_ptr(),
            buf.len(),
            fmt.as_ptr(),
            7_i32,
            3_i32,
            701_i32,
            c"tail".as_ptr(),
            1.5_f64,
            &mut count,
        )
    };
    assert_eq!(written, 18);
    assert_eq!(count, 18);
    let expected: Vec<i32> = "%7.3Q:701:tail:1.5\0".chars().map(|c| c as i32).collect();
    assert_eq!(&buf[..expected.len()], expected);
    assert!(buf[expected.len()..].iter().all(|&v| v == 0x5a));
}

#[test]
fn swprintf_unknown_conversions_truncation_reports_e2big() {
    let fmt: Vec<libc::wchar_t> = "%*qQ:%d\0".chars().map(|c| c as i32).collect();
    let mut buf = [0x5a_i32; 8];
    // SAFETY: format and promoted arguments agree, capacities fit the live
    // buffer, and errno points to this thread's writable slot.
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
        assert_eq!(
            swprintf(buf.as_mut_ptr(), 2, fmt.as_ptr(), 7_i32, 701_i32),
            -1
        );
        assert_eq!(*frankenlibc_abi::errno_abi::__errno_location(), libc::E2BIG);
        assert_eq!(buf, [b'%' as i32, 0, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a]);
        *frankenlibc_abi::errno_abi::__errno_location() = 91;
        assert_eq!(
            swprintf(buf.as_mut_ptr(), 0, fmt.as_ptr(), 7_i32, 701_i32),
            -1
        );
        assert_eq!(*frankenlibc_abi::errno_abi::__errno_location(), 91);
    }
}

#[test]
fn swprintf_unknown_conversions_and_errno_message_consume_no_value() {
    let fmt: Vec<libc::wchar_t> = "%m:%d:%s\0".chars().map(|c| c as i32).collect();
    let mut buf = [0_i32; 64];
    // SAFETY: errno is this thread's slot; the terminated format/string and
    // promoted integer agree with the caller's writable wchar buffer.
    let written = unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = libc::EINVAL;
        swprintf(
            buf.as_mut_ptr(),
            buf.len(),
            fmt.as_ptr(),
            701_i32,
            c"tail".as_ptr(),
        )
    };
    let expected: Vec<i32> = "Invalid argument:701:tail\0"
        .chars()
        .map(|c| c as i32)
        .collect();
    assert_eq!(written as usize, expected.len() - 1);
    assert_eq!(&buf[..expected.len()], expected);
}

struct StdioGlobalStreamGuard {
    _guard: MutexGuard<'static, ()>,
    old_stdin: *mut c_void,
    old_stdout: *mut c_void,
}

impl StdioGlobalStreamGuard {
    unsafe fn install(new_stdin: *mut c_void, new_stdout: *mut c_void) -> Self {
        let guard = STDIO_GLOBAL_STREAM_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let old_stdin = unsafe { frankenlibc_abi::stdio_abi::stdin };
        let old_stdout = unsafe { frankenlibc_abi::stdio_abi::stdout };
        unsafe {
            frankenlibc_abi::stdio_abi::stdin = new_stdin;
            frankenlibc_abi::stdio_abi::stdout = new_stdout;
        }
        Self {
            _guard: guard,
            old_stdin,
            old_stdout,
        }
    }
}

impl Drop for StdioGlobalStreamGuard {
    fn drop(&mut self) {
        unsafe {
            frankenlibc_abi::stdio_abi::stdin = self.old_stdin;
            frankenlibc_abi::stdio_abi::stdout = self.old_stdout;
        }
    }
}

fn errno_value() -> i32 {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

fn set_errno(value: i32) {
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = value;
    }
}

/// Helper: build a NUL-terminated wide string from ASCII bytes.
fn wstr(s: &[u8]) -> Vec<u32> {
    let mut v: Vec<u32> = s.iter().map(|&b| b as u32).collect();
    v.push(0);
    v
}

unsafe fn malloc_unterminated_wide(wchars: &[u32]) -> *mut u32 {
    let ptr = unsafe { malloc(std::mem::size_of_val(wchars)) }.cast::<u32>();
    assert!(!ptr.is_null());
    unsafe { std::ptr::copy_nonoverlapping(wchars.as_ptr(), ptr, wchars.len()) };
    ptr
}

// ── wcslen ──────────────────────────────────────────────────────────────────

#[test]
fn wcslen_counts_to_nul() {
    let s = wstr(b"hello");
    assert_eq!(unsafe { wcslen(s.as_ptr()) }, 5);
}

#[test]
fn wcslen_empty_string() {
    let s = wstr(b"");
    assert_eq!(unsafe { wcslen(s.as_ptr()) }, 0);
}

#[test]
fn wcslen_bounds_tracked_unterminated_input() {
    unsafe {
        let src = malloc_unterminated_wide(&[b'A' as u32, b'B' as u32, b'C' as u32]);

        assert_eq!(wcslen(src), 3);

        free(src.cast());
    }
}

// ── wcscpy / wcsncpy ───────────────────────────────────────────────────────

#[test]
fn wcscpy_copies_full_string() {
    let src = wstr(b"abc");
    let mut dst = [0u32; 8];
    let ret = unsafe { wcscpy(dst.as_mut_ptr(), src.as_ptr()) };
    assert_eq!(ret, dst.as_mut_ptr());
    assert_eq!(dst[0], b'a' as u32);
    assert_eq!(dst[1], b'b' as u32);
    assert_eq!(dst[2], b'c' as u32);
    assert_eq!(dst[3], 0);
}

#[test]
fn wcscpy_bounds_tracked_unterminated_source() {
    unsafe {
        let src = malloc_unterminated_wide(&[b'A' as u32, b'B' as u32, b'C' as u32]);
        let mut dst = [0xFFFFu32; 5];

        let ret = wcscpy(dst.as_mut_ptr(), src);

        assert_eq!(ret, dst.as_mut_ptr());
        assert_eq!(dst[0], b'A' as u32);
        assert_eq!(dst[1], b'B' as u32);
        assert_eq!(dst[2], b'C' as u32);
        assert_eq!(dst[3], 0);
        assert_eq!(dst[4], 0xFFFF);

        free(src.cast());
    }
}

#[test]
fn wcsncpy_pads_with_nul() {
    let src = wstr(b"hi");
    let mut dst = [0xFFu32; 6];
    let ret = unsafe { wcsncpy(dst.as_mut_ptr(), src.as_ptr(), 5) };
    assert_eq!(ret, dst.as_mut_ptr());
    assert_eq!(dst[0], b'h' as u32);
    assert_eq!(dst[1], b'i' as u32);
    // Positions 2..5 should be NUL-padded.
    assert_eq!(dst[2], 0);
    assert_eq!(dst[3], 0);
    assert_eq!(dst[4], 0);
    // Position 5 untouched.
    assert_eq!(dst[5], 0xFF);
}

#[test]
fn wcsncpy_truncates_when_n_smaller() {
    let src = wstr(b"hello");
    let mut dst = [0u32; 4];
    unsafe { wcsncpy(dst.as_mut_ptr(), src.as_ptr(), 3) };
    assert_eq!(dst[0], b'h' as u32);
    assert_eq!(dst[1], b'e' as u32);
    assert_eq!(dst[2], b'l' as u32);
}

// ── wcscat / wcsncat ────────────────────────────────────────────────────────

#[test]
fn wcscat_appends_source() {
    let suffix = wstr(b"world");
    let mut buf = [0u32; 16];
    buf[0] = b'h' as u32;
    buf[1] = b'i' as u32;
    buf[2] = 0;
    let ret = unsafe { wcscat(buf.as_mut_ptr(), suffix.as_ptr()) };
    assert_eq!(ret, buf.as_mut_ptr());
    assert_eq!(unsafe { wcslen(buf.as_ptr()) }, 7);
}

#[test]
fn wcsncat_limits_appended_chars() {
    let suffix = wstr(b"world");
    let mut buf = [0u32; 16];
    buf[0] = b'h' as u32;
    buf[1] = b'i' as u32;
    buf[2] = 0;
    unsafe { wcsncat(buf.as_mut_ptr(), suffix.as_ptr(), 3) };
    // "hi" + "wor" = 5
    assert_eq!(unsafe { wcslen(buf.as_ptr()) }, 5);
    assert_eq!(buf[4], b'r' as u32);
    assert_eq!(buf[5], 0); // NUL-terminated
}

// ── wcscmp / wcsncmp ────────────────────────────────────────────────────────

#[test]
fn wcscmp_compares_strings() {
    let a = wstr(b"abc");
    let b = wstr(b"abd");
    assert!(unsafe { wcscmp(a.as_ptr(), b.as_ptr()) } < 0);
    assert!(unsafe { wcscmp(b.as_ptr(), a.as_ptr()) } > 0);
    assert_eq!(unsafe { wcscmp(a.as_ptr(), a.as_ptr()) }, 0);
}

#[test]
fn wcsncmp_compares_up_to_n() {
    let a = wstr(b"abcX");
    let b = wstr(b"abcY");
    assert_eq!(unsafe { wcsncmp(a.as_ptr(), b.as_ptr(), 3) }, 0);
    assert_ne!(unsafe { wcsncmp(a.as_ptr(), b.as_ptr(), 4) }, 0);
    assert_eq!(unsafe { wcsncmp(a.as_ptr(), b.as_ptr(), 0) }, 0);
}

// ── wcschr / wcsrchr / wcschrnul ────────────────────────────────────────────

#[test]
fn wcschr_finds_first_occurrence() {
    let s = wstr(b"abcbc");
    let ptr = unsafe { wcschr(s.as_ptr(), b'b' as u32) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { ptr.offset_from(s.as_ptr()) }, 1);
}

#[test]
fn wcschr_returns_null_for_missing() {
    let s = wstr(b"abc");
    assert!(unsafe { wcschr(s.as_ptr(), b'z' as u32) }.is_null());
}

#[test]
fn wcschr_finds_nul_terminator() {
    let s = wstr(b"abc");
    let ptr = unsafe { wcschr(s.as_ptr(), 0) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { ptr.offset_from(s.as_ptr()) }, 3);
}

#[test]
fn wcsrchr_finds_last_occurrence() {
    let s = wstr(b"abcbc");
    let ptr = unsafe { wcsrchr(s.as_ptr(), b'b' as u32) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { ptr.offset_from(s.as_ptr()) }, 3);
}

#[test]
fn wcsrchr_returns_null_for_missing() {
    let s = wstr(b"abc");
    assert!(unsafe { wcsrchr(s.as_ptr(), b'z' as u32) }.is_null());
}

#[test]
fn wcschrnul_returns_nul_position_for_missing() {
    let s = wstr(b"abc");
    let ptr = unsafe { wcschrnul(s.as_ptr() as *const libc::wchar_t, b'z' as libc::wchar_t) };
    assert!(!ptr.is_null());
    assert_eq!(
        unsafe { ptr.offset_from(s.as_ptr() as *const libc::wchar_t) },
        3
    );
    assert_eq!(unsafe { *ptr }, 0);
}

// ── wcsstr ──────────────────────────────────────────────────────────────────

#[test]
fn wcsstr_finds_substring() {
    let hay = wstr(b"hello world");
    let needle = wstr(b"world");
    let ptr = unsafe { wcsstr(hay.as_ptr(), needle.as_ptr()) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { ptr.offset_from(hay.as_ptr()) }, 6);
}

#[test]
fn wcsstr_returns_null_for_missing() {
    let hay = wstr(b"hello");
    let needle = wstr(b"xyz");
    assert!(unsafe { wcsstr(hay.as_ptr(), needle.as_ptr()) }.is_null());
}

#[test]
fn wcsstr_empty_needle_returns_haystack() {
    let hay = wstr(b"hello");
    let needle = wstr(b"");
    let ptr = unsafe { wcsstr(hay.as_ptr(), needle.as_ptr()) };
    assert_eq!(ptr, hay.as_ptr() as *mut u32);
}

// ── wcsspn / wcscspn / wcspbrk ──────────────────────────────────────────────

#[test]
fn wcsspn_counts_accepted_prefix() {
    let s = wstr(b"abcdef");
    let accept = wstr(b"cba");
    assert_eq!(unsafe { wcsspn(s.as_ptr(), accept.as_ptr()) }, 3);
}

#[test]
fn wcscspn_counts_rejected_prefix() {
    let s = wstr(b"abcdef");
    let reject = wstr(b"dc");
    assert_eq!(unsafe { wcscspn(s.as_ptr(), reject.as_ptr()) }, 2);
}

#[test]
fn wcspbrk_finds_first_matching_char() {
    let s = wstr(b"hello world");
    let accept = wstr(b"ow");
    let ptr = unsafe { wcspbrk(s.as_ptr(), accept.as_ptr()) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { *ptr }, b'o' as u32);
}

#[test]
fn wcspbrk_returns_null_when_no_match() {
    let s = wstr(b"hello");
    let accept = wstr(b"xyz");
    assert!(unsafe { wcspbrk(s.as_ptr(), accept.as_ptr()) }.is_null());
}

// ── wcstok ──────────────────────────────────────────────────────────────────

#[test]
fn wcstok_splits_on_delimiters() {
    let mut s = wstr(b"one,two,,three");
    let delim = wstr(b",");
    let mut save: *mut u32 = std::ptr::null_mut();

    let tok1 = unsafe { wcstok(s.as_mut_ptr(), delim.as_ptr(), &mut save) };
    assert!(!tok1.is_null());
    assert_eq!(unsafe { wcslen(tok1) }, 3); // "one"

    let tok2 = unsafe { wcstok(std::ptr::null_mut(), delim.as_ptr(), &mut save) };
    assert!(!tok2.is_null());
    assert_eq!(unsafe { wcslen(tok2) }, 3); // "two"

    let tok3 = unsafe { wcstok(std::ptr::null_mut(), delim.as_ptr(), &mut save) };
    assert!(!tok3.is_null());
    assert_eq!(unsafe { wcslen(tok3) }, 5); // "three"

    let tok4 = unsafe { wcstok(std::ptr::null_mut(), delim.as_ptr(), &mut save) };
    assert!(tok4.is_null());
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn wcstok_rejects_tracked_unterminated_delimiter() {
    unsafe {
        let mut s = wstr(b"one,two");
        let delim = malloc_unterminated_wide(&[b',' as u32]);
        let mut save: *mut u32 = std::ptr::null_mut();

        let tok = wcstok(s.as_mut_ptr(), delim, &mut save);

        assert!(tok.is_null());
        assert!(save.is_null());
        assert_eq!(s, wstr(b"one,two"));
        free(delim.cast());
    }
}

// ── wmemcpy / wmemmove / wmemset / wmemcmp / wmemchr / wmemrchr ─────────────

#[test]
fn wmemcpy_copies_elements() {
    let src = wstr(b"abcde");
    let mut dst = [0u32; 5];
    let ret = unsafe { wmemcpy(dst.as_mut_ptr(), src.as_ptr(), 5) };
    assert_eq!(ret, dst.as_mut_ptr());
    assert_eq!(dst[0], b'a' as u32);
    assert_eq!(dst[4], b'e' as u32);
}

#[test]
fn wmemmove_handles_overlap() {
    let mut buf = [1u32, 2, 3, 4, 5, 0, 0, 0];
    // Move [1,2,3,4,5] two positions right.
    unsafe { wmemmove(buf.as_mut_ptr().add(2), buf.as_ptr(), 5) };
    assert_eq!(buf[2], 1);
    assert_eq!(buf[6], 5);
}

#[test]
fn wmemset_fills_elements() {
    let mut buf = [0u32; 5];
    let ret = unsafe { wmemset(buf.as_mut_ptr(), 42, 3) };
    assert_eq!(ret, buf.as_mut_ptr());
    assert_eq!(buf[0], 42);
    assert_eq!(buf[2], 42);
    assert_eq!(buf[3], 0); // Untouched
}

#[test]
fn wmemcmp_compares_elements() {
    let a = [1u32, 2, 3];
    let b = [1u32, 2, 4];
    assert_eq!(unsafe { wmemcmp(a.as_ptr(), b.as_ptr(), 2) }, 0);
    assert!(unsafe { wmemcmp(a.as_ptr(), b.as_ptr(), 3) } < 0);
    assert!(unsafe { wmemcmp(b.as_ptr(), a.as_ptr(), 3) } > 0);
    assert_eq!(unsafe { wmemcmp(a.as_ptr(), b.as_ptr(), 0) }, 0);
}

#[test]
fn wmemchr_finds_element() {
    let buf = [10u32, 20, 30, 40];
    let ptr = unsafe { wmemchr(buf.as_ptr(), 30, 4) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { ptr.offset_from(buf.as_ptr()) }, 2);
}

#[test]
fn wmemchr_returns_null_when_not_found() {
    let buf = [10u32, 20, 30];
    assert!(unsafe { wmemchr(buf.as_ptr(), 99, 3) }.is_null());
}

#[test]
fn wmemrchr_finds_last_element() {
    let buf = [10u32, 20, 30, 20, 40];
    let ptr = unsafe { wmemrchr(buf.as_ptr(), 20, 5) };
    assert!(!ptr.is_null());
    assert_eq!(unsafe { ptr.offset_from(buf.as_ptr()) }, 3);
}

// ── wcsdup ──────────────────────────────────────────────────────────────────

#[test]
fn wcsdup_duplicates_string() {
    let s = wstr(b"test");
    let dup = unsafe { wcsdup(s.as_ptr()) };
    assert!(!dup.is_null());
    assert_eq!(unsafe { wcslen(dup) }, 4);
    assert_eq!(unsafe { *dup }, b't' as u32);
    assert_eq!(unsafe { *dup.add(3) }, b't' as u32);
    assert_eq!(unsafe { *dup.add(4) }, 0);
    unsafe { frankenlibc_abi::malloc_abi::free(dup.cast()) };
}

// ── wcpcpy / wcpncpy ───────────────────────────────────────────────────────

#[test]
fn wcpcpy_returns_pointer_to_nul() {
    let src = wstr(b"abc");
    let mut dst = [0u32; 8];
    let end = unsafe { wcpcpy(dst.as_mut_ptr(), src.as_ptr()) };
    // wcpcpy returns pointer to the NUL terminator.
    assert_eq!(unsafe { end.offset_from(dst.as_ptr()) }, 3);
    assert_eq!(unsafe { *end }, 0);
    assert_eq!(dst[0], b'a' as u32);
}

#[test]
fn wcpncpy_returns_pointer_past_last_written() {
    let src = wstr(b"hi");
    let mut dst = [0xFFu32; 6];
    let end = unsafe { wcpncpy(dst.as_mut_ptr(), src.as_ptr(), 5) };
    // wcpncpy returns dst + min(wcslen(src), n), padded with NULs.
    assert_eq!(unsafe { end.offset_from(dst.as_ptr()) }, 2);
    assert_eq!(dst[2], 0);
    assert_eq!(dst[4], 0);
}

// ── wcscasecmp / wcsncasecmp ────────────────────────────────────────────────

#[test]
fn wcscasecmp_ignores_case() {
    let a = wstr(b"Hello");
    let b = wstr(b"hELLO");
    assert_eq!(unsafe { wcscasecmp(a.as_ptr(), b.as_ptr()) }, 0);

    let c = wstr(b"abc");
    let d = wstr(b"abd");
    assert!(unsafe { wcscasecmp(c.as_ptr(), d.as_ptr()) } < 0);
}

#[test]
fn wcsncasecmp_compares_up_to_n() {
    let a = wstr(b"Hello World");
    let b = wstr(b"hELLO EARTH");
    assert_eq!(unsafe { wcsncasecmp(a.as_ptr(), b.as_ptr(), 5) }, 0);
    assert_eq!(unsafe { wcsncasecmp(a.as_ptr(), b.as_ptr(), 6) }, 0); // space == space
    assert_ne!(unsafe { wcsncasecmp(a.as_ptr(), b.as_ptr(), 7) }, 0); // W != E
}

// ── wcslcpy / wcslcat ───────────────────────────────────────────────────────

#[test]
fn wcslcpy_copies_and_returns_src_len() {
    let src = wstr(b"hello");
    let mut dst = [0u32; 4];
    let n = unsafe {
        wcslcpy(
            dst.as_mut_ptr() as *mut libc::wchar_t,
            src.as_ptr() as *const libc::wchar_t,
            4,
        )
    };
    assert_eq!(n, 5); // Length of src
    // Should truncate to "hel\0"
    assert_eq!(dst[0], b'h' as u32);
    assert_eq!(dst[2], b'l' as u32);
    assert_eq!(dst[3], 0);
}

#[test]
fn wcslcpy_bounds_tracked_unterminated_source() {
    unsafe {
        let src = malloc_unterminated_wide(&[b'A' as u32, b'B' as u32, b'C' as u32]);
        let mut dst = [0u32; 2];

        let n = wcslcpy(
            dst.as_mut_ptr().cast::<libc::wchar_t>(),
            src.cast::<libc::wchar_t>(),
            dst.len(),
        );
        assert_eq!(n, 3);
        assert_eq!(dst[0], b'A' as u32);
        assert_eq!(dst[1], 0);

        free(src.cast());
    }
}

#[test]
fn wcslcat_appends_and_returns_total_len() {
    let suffix = wstr(b"world");
    let mut buf = [0u32; 10];
    buf[0] = b'h' as u32;
    buf[1] = b'i' as u32;
    buf[2] = 0;
    let n = unsafe {
        wcslcat(
            buf.as_mut_ptr() as *mut libc::wchar_t,
            suffix.as_ptr() as *const libc::wchar_t,
            10,
        )
    };
    assert_eq!(n, 7); // 2 + 5
    assert_eq!(unsafe { wcslen(buf.as_ptr()) }, 7);
}

#[test]
fn wcslcat_bounds_tracked_unterminated_source() {
    unsafe {
        let src = malloc_unterminated_wide(&[b'A' as u32, b'B' as u32, b'C' as u32]);
        let mut dst = [0u32; 3];
        dst[0] = b'X' as u32;
        dst[1] = 0;

        let n = wcslcat(
            dst.as_mut_ptr().cast::<libc::wchar_t>(),
            src.cast::<libc::wchar_t>(),
            dst.len(),
        );
        assert_eq!(n, 4);
        assert_eq!(dst[0], b'X' as u32);
        assert_eq!(dst[1], b'A' as u32);
        assert_eq!(dst[2], 0);

        free(src.cast());
    }
}

// ── wcstoimax / wcstoumax ───────────────────────────────────────────────────

#[test]
fn wcstoimax_parses_signed() {
    let s = wstr(b"-42");
    let mut end: *mut u32 = std::ptr::null_mut();
    let v = unsafe { wcstoimax(s.as_ptr(), &mut end, 10) };
    assert_eq!(v, -42);
    assert_eq!(unsafe { end.offset_from(s.as_ptr()) }, 3);
}

#[test]
fn wcstoumax_parses_unsigned() {
    let s = wstr(b"99");
    let mut end: *mut u32 = std::ptr::null_mut();
    let v = unsafe { wcstoumax(s.as_ptr(), &mut end, 10) };
    assert_eq!(v, 99);
}

// ── towupper / towlower ─────────────────────────────────────────────────────

#[test]
fn towupper_converts_lowercase() {
    assert_eq!(unsafe { towupper(b'a' as u32) }, b'A' as u32);
    assert_eq!(unsafe { towupper(b'Z' as u32) }, b'Z' as u32);
    assert_eq!(unsafe { towupper(b'5' as u32) }, b'5' as u32);
}

#[test]
fn towlower_converts_uppercase() {
    assert_eq!(unsafe { towlower(b'A' as u32) }, b'a' as u32);
    assert_eq!(unsafe { towlower(b'z' as u32) }, b'z' as u32);
    assert_eq!(unsafe { towlower(b'5' as u32) }, b'5' as u32);
}

// ── isw* classification ─────────────────────────────────────────────────────

#[test]
fn iswalnum_identifies_alphanumerics() {
    assert_ne!(unsafe { iswalnum(b'a' as u32) }, 0);
    assert_ne!(unsafe { iswalnum(b'Z' as u32) }, 0);
    assert_ne!(unsafe { iswalnum(b'5' as u32) }, 0);
    assert_eq!(unsafe { iswalnum(b' ' as u32) }, 0);
    assert_eq!(unsafe { iswalnum(b'!' as u32) }, 0);
}

#[test]
fn iswalpha_identifies_letters() {
    assert_ne!(unsafe { iswalpha(b'a' as u32) }, 0);
    assert_ne!(unsafe { iswalpha(b'Z' as u32) }, 0);
    assert_eq!(unsafe { iswalpha(b'5' as u32) }, 0);
}

#[test]
fn iswdigit_identifies_digits() {
    assert_ne!(unsafe { iswdigit(b'0' as u32) }, 0);
    assert_ne!(unsafe { iswdigit(b'9' as u32) }, 0);
    assert_eq!(unsafe { iswdigit(b'a' as u32) }, 0);
}

#[test]
fn iswlower_and_iswupper() {
    assert_ne!(unsafe { iswlower(b'a' as u32) }, 0);
    assert_eq!(unsafe { iswlower(b'A' as u32) }, 0);
    assert_ne!(unsafe { iswupper(b'A' as u32) }, 0);
    assert_eq!(unsafe { iswupper(b'a' as u32) }, 0);
}

#[test]
fn iswspace_identifies_whitespace() {
    assert_ne!(unsafe { iswspace(b' ' as u32) }, 0);
    assert_ne!(unsafe { iswspace(b'\t' as u32) }, 0);
    assert_ne!(unsafe { iswspace(b'\n' as u32) }, 0);
    assert_eq!(unsafe { iswspace(b'a' as u32) }, 0);
}

#[test]
fn iswprint_identifies_printable() {
    assert_ne!(unsafe { iswprint(b'a' as u32) }, 0);
    assert_ne!(unsafe { iswprint(b' ' as u32) }, 0);
    assert_eq!(unsafe { iswprint(0x01) }, 0); // SOH control char
}

#[test]
fn iswblank_identifies_horizontal_whitespace() {
    assert_ne!(unsafe { iswblank(b' ' as u32) }, 0);
    assert_ne!(unsafe { iswblank(b'\t' as u32) }, 0);
    assert_eq!(unsafe { iswblank(b'\n' as u32) }, 0);
    assert_eq!(unsafe { iswblank(b'a' as u32) }, 0);
}

#[test]
fn iswcntrl_identifies_control_chars() {
    assert_ne!(unsafe { iswcntrl(0x00) }, 0); // NUL
    assert_ne!(unsafe { iswcntrl(0x1F) }, 0); // US
    assert_ne!(unsafe { iswcntrl(0x7F) }, 0); // DEL
    assert_eq!(unsafe { iswcntrl(b'a' as u32) }, 0);
}

#[test]
fn iswgraph_identifies_visible_chars() {
    assert_ne!(unsafe { iswgraph(b'a' as u32) }, 0);
    assert_ne!(unsafe { iswgraph(b'!' as u32) }, 0);
    assert_eq!(unsafe { iswgraph(b' ' as u32) }, 0);
    assert_eq!(unsafe { iswgraph(0x01) }, 0);
}

#[test]
fn iswpunct_identifies_punctuation() {
    assert_ne!(unsafe { iswpunct(b'!' as u32) }, 0);
    assert_ne!(unsafe { iswpunct(b'.' as u32) }, 0);
    assert_eq!(unsafe { iswpunct(b'a' as u32) }, 0);
    assert_eq!(unsafe { iswpunct(b' ' as u32) }, 0);
}

#[test]
fn iswxdigit_identifies_hex_digits() {
    assert_ne!(unsafe { iswxdigit(b'0' as u32) }, 0);
    assert_ne!(unsafe { iswxdigit(b'a' as u32) }, 0);
    assert_ne!(unsafe { iswxdigit(b'F' as u32) }, 0);
    assert_eq!(unsafe { iswxdigit(b'g' as u32) }, 0);
}

// ── wcwidth ─────────────────────────────────────────────────────────────────

#[test]
fn wcwidth_reports_display_width() {
    let _utf8 = utf8_locale();
    assert_eq!(unsafe { wcwidth(b'A' as u32) }, 1);
    assert_eq!(unsafe { wcwidth(0x754c) }, 2); // CJK char '界'
    assert_eq!(unsafe { wcwidth(0) }, 0); // NUL
    assert_eq!(unsafe { wcwidth(0x1AB0) }, 0); // Combining Diacritical Marks Extended
    assert_eq!(unsafe { wcwidth(0x1DC0) }, 0); // Combining Diacritical Marks Supplement
    assert_eq!(unsafe { wcwidth(0x20D0) }, 0); // Combining Diacritical Marks for Symbols
    assert_eq!(unsafe { wcwidth(0x3099) }, 0); // COMBINING KATAKANA-HIRAGANA VOICED SOUND MARK
    assert_eq!(unsafe { wcwidth(0xFE20) }, 0); // Combining Half Marks
}

/// glibc's built-in C locale classifies, maps and measures ASCII only
/// (measured on glibc 2.43: iswalpha(0xE9)=0, towupper(0xE9)=0xE9,
/// wcwidth(0x754C)=-1, wcwidth(0x7F)=-1).
#[test]
fn wide_ctype_in_c_locale_is_ascii_only() {
    let _lock = utf8_locale();
    let c = std::ffi::CString::new("C").unwrap();
    unsafe { frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c.as_ptr()) };
    assert_eq!(unsafe { iswalpha(0xE9) }, 0);
    assert_ne!(unsafe { iswalpha(b'z' as u32) }, 0);
    assert_eq!(unsafe { towupper(0xE9) }, 0xE9);
    assert_eq!(unsafe { towupper(b'q' as u32) }, b'Q' as u32);
    assert_eq!(unsafe { wcwidth(0x754C) }, -1);
    assert_eq!(unsafe { wcwidth(0x7F) }, -1);
    assert_eq!(unsafe { wcwidth(b'A' as u32) }, 1);
    assert_eq!(unsafe { wcwidth(0) }, 0);
}

// ── wctype / iswctype ───────────────────────────────────────────────────────

#[test]
fn wctype_and_iswctype_classify_by_name() {
    let alpha = unsafe { wctype(c"alpha".as_ptr().cast()) };
    assert_ne!(alpha, 0);
    assert_ne!(unsafe { iswctype(b'A' as u32, alpha) }, 0);
    assert_eq!(unsafe { iswctype(b'5' as u32, alpha) }, 0);

    let digit = unsafe { wctype(c"digit".as_ptr().cast()) };
    assert_ne!(digit, 0);
    assert_ne!(unsafe { iswctype(b'9' as u32, digit) }, 0);
    assert_eq!(unsafe { iswctype(b'A' as u32, digit) }, 0);
}

#[test]
fn wctype_returns_zero_for_unknown() {
    assert_eq!(unsafe { wctype(c"bogus".as_ptr().cast()) }, 0);
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn wctype_and_wctrans_reject_unterminated_names() {
    unsafe {
        let unterminated_class = malloc(5).cast::<u8>();
        assert!(!unterminated_class.is_null());
        std::ptr::copy_nonoverlapping(b"alpha".as_ptr(), unterminated_class, 5);
        let class_desc = wctype(unterminated_class);
        free(unterminated_class.cast());
        assert_eq!(class_desc, 0);

        let unterminated_transform = malloc(7).cast::<u8>();
        assert!(!unterminated_transform.is_null());
        std::ptr::copy_nonoverlapping(b"toupper".as_ptr(), unterminated_transform, 7);
        let transform_desc = wctrans_l(unterminated_transform, std::ptr::null_mut());
        free(unterminated_transform.cast());
        assert_eq!(transform_desc, 0);
    }
}

#[test]
fn wctrans_l_returns_transform_descriptors() {
    let upper = unsafe { wctrans_l(c"toupper".as_ptr().cast(), std::ptr::null_mut()) };
    let lower = unsafe { wctrans_l(c"tolower".as_ptr().cast(), std::ptr::null_mut()) };
    assert_ne!(upper, 0);
    assert_ne!(lower, 0);
    assert_eq!(
        unsafe { towctrans_l(b'a' as u32, upper, std::ptr::null_mut()) },
        b'A' as u32
    );
    assert_eq!(
        unsafe { towctrans_l(b'Z' as u32, lower, std::ptr::null_mut()) },
        b'z' as u32
    );
}

// ── towupper_l / towlower_l (null locale = C locale) ────────────────────────

#[test]
fn towupper_l_null_locale_matches_base() {
    let loc = std::ptr::null_mut();
    for c in 0u32..=127 {
        assert_eq!(
            unsafe { towupper_l(c, loc) },
            unsafe { towupper(c) },
            "mismatch at {c}"
        );
    }
}

#[test]
fn towlower_l_null_locale_matches_base() {
    let loc = std::ptr::null_mut();
    for c in 0u32..=127 {
        assert_eq!(
            unsafe { towlower_l(c, loc) },
            unsafe { towlower(c) },
            "mismatch at {c}"
        );
    }
}

// ── isw*_l locale variants sweep ────────────────────────────────────────────

#[test]
fn iswalnum_l_matches_base_for_ascii() {
    let loc = std::ptr::null_mut();
    for c in 0u32..=127 {
        assert_eq!(
            unsafe { iswalnum_l(c, loc) },
            unsafe { iswalnum(c) },
            "iswalnum mismatch at {c}"
        );
    }
}

#[test]
fn iswalpha_l_matches_base_for_ascii() {
    let loc = std::ptr::null_mut();
    for c in 0u32..=127 {
        assert_eq!(
            unsafe { iswalpha_l(c, loc) },
            unsafe { iswalpha(c) },
            "iswalpha mismatch at {c}"
        );
    }
}

#[test]
fn iswdigit_l_matches_base_for_ascii() {
    let loc = std::ptr::null_mut();
    for c in 0u32..=127 {
        assert_eq!(
            unsafe { iswdigit_l(c, loc) },
            unsafe { iswdigit(c) },
            "iswdigit mismatch at {c}"
        );
    }
}

#[test]
fn iswspace_l_matches_base_for_ascii() {
    let loc = std::ptr::null_mut();
    for c in 0u32..=127 {
        assert_eq!(
            unsafe { iswspace_l(c, loc) },
            unsafe { iswspace(c) },
            "iswspace mismatch at {c}"
        );
    }
}

// ── mblen / mbtowc / wctomb ────────────────────────────────────────────────

/// Switch to a UTF-8 locale for the duration of a multibyte test, and put the
/// previous one back.
///
/// fl starts in the POSIX C locale, where the charset is ASCII and any byte
/// `>= 0x80` is EILSEQ. That is not a quirk — it is what glibc does. Measured on
/// this host with a C program that never calls setlocale:
///
/// ```text
///   MB_CUR_MAX = 1
///   mblen("\xc3\xa9") = -1, errno = EILSEQ
/// ```
///
/// and both `setlocale(LC_ALL, "")` (with LANG=en_US.UTF-8) and
/// `setlocale(LC_ALL, "C.UTF-8")` then give MB_CUR_MAX 6 and mblen 2. So a test
/// that wants to convert UTF-8 has to ask for it, like any real program.
///
/// The lock matters: `setlocale` is process-global and libtest runs these on
/// parallel threads, so without serialising, one test's locale leaks into
/// another's assertions.
fn utf8_locale() -> Utf8LocaleGuard {
    static LOCALE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let guard = LOCALE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SAFETY: NUL-terminated locale name; the returned pointer is fl's static
    // buffer, read before any further setlocale call.
    let previous = unsafe {
        let current = frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, std::ptr::null());
        let saved = if current.is_null() {
            String::from("C")
        } else {
            std::ffi::CStr::from_ptr(current)
                .to_string_lossy()
                .into_owned()
        };
        let utf8 = std::ffi::CString::new("C.UTF-8").expect("no NUL");
        frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, utf8.as_ptr());
        saved
    };
    Utf8LocaleGuard {
        previous,
        _guard: guard,
    }
}

struct Utf8LocaleGuard {
    previous: String,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Drop for Utf8LocaleGuard {
    fn drop(&mut self) {
        if let Ok(name) = std::ffi::CString::new(self.previous.as_str()) {
            // SAFETY: NUL-terminated name captured from setlocale itself.
            unsafe { frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, name.as_ptr()) };
        }
    }
}

#[test]
fn mblen_measures_ascii_and_multibyte() {
    let _utf8 = utf8_locale();
    let ascii = *b"A";
    assert_eq!(unsafe { mblen(ascii.as_ptr(), 1) }, 1);

    let utf8 = [0xC3u8, 0xA9]; // é
    assert_eq!(unsafe { mblen(utf8.as_ptr(), 2) }, 2);

    // NUL byte returns 0
    let nul = [0u8];
    assert_eq!(unsafe { mblen(nul.as_ptr(), 1) }, 0);
}

#[test]
fn mbtowc_converts_ascii() {
    let mut wc: u32 = 0;
    let ascii = *b"X";
    let n = unsafe { mbtowc(&mut wc, ascii.as_ptr(), 1) };
    assert_eq!(n, 1);
    assert_eq!(wc, b'X' as u32);
}

#[test]
fn mbtowc_converts_multibyte() {
    let _utf8 = utf8_locale();
    let mut wc: u32 = 0;
    let utf8 = [0xC3u8, 0xA9]; // é
    let n = unsafe { mbtowc(&mut wc, utf8.as_ptr(), 2) };
    assert_eq!(n, 2);
    assert_eq!(wc, 'é' as u32);
}

#[test]
fn wctomb_encodes_ascii() {
    let mut buf = [0u8; 4];
    let n = unsafe { wctomb(buf.as_mut_ptr(), b'A' as u32) };
    assert_eq!(n, 1);
    assert_eq!(buf[0], b'A');
}

#[test]
fn wctomb_encodes_multibyte() {
    let _utf8 = utf8_locale();
    let mut buf = [0u8; 4];
    let n = unsafe { wctomb(buf.as_mut_ptr(), 'é' as u32) };
    assert_eq!(n, 2);
    assert_eq!(buf[0], 0xC3);
    assert_eq!(buf[1], 0xA9);
}

// ── mbstowcs / wcstombs ────────────────────────────────────────────────────

#[test]
fn mbstowcs_converts_utf8_to_wide() {
    let _utf8 = utf8_locale();
    let src = b"A\xC3\xA9\0"; // "Aé"
    let mut dst = [0u32; 4];
    let n = unsafe { mbstowcs(dst.as_mut_ptr(), src.as_ptr(), 4) };
    assert_eq!(n, 2);
    assert_eq!(dst[0], b'A' as u32);
    assert_eq!(dst[1], 'é' as u32);
    assert_eq!(dst[2], 0);
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn mbstowcs_rejects_unterminated_known_input() {
    unsafe {
        let src = malloc(3).cast::<u8>();
        assert!(!src.is_null());
        std::ptr::copy_nonoverlapping(b"ABC".as_ptr(), src, 3);

        let mut dst = [0u32; 4];
        set_errno(0);
        let n = mbstowcs(dst.as_mut_ptr(), src, dst.len());
        assert_eq!(n, usize::MAX);
        assert_eq!(errno_value(), libc::EILSEQ);

        free(src.cast());
    }
}

#[test]
fn wcstombs_converts_wide_to_utf8() {
    let _utf8 = utf8_locale();
    let src = [b'A' as u32, 'é' as u32, 0];
    let mut dst = [0u8; 8];
    let n = unsafe { wcstombs(dst.as_mut_ptr(), src.as_ptr(), 8) };
    assert_eq!(n, 3);
    assert_eq!(dst[0], b'A');
    assert_eq!(dst[1], 0xC3);
    assert_eq!(dst[2], 0xA9);
    assert_eq!(dst[3], 0);
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn wcstombs_rejects_tracked_unterminated_wide_input() {
    unsafe {
        let src = malloc_unterminated_wide(&[b'A' as u32, b'B' as u32]);
        let mut dst = [0u8; 8];

        set_errno(0);
        let n = wcstombs(dst.as_mut_ptr(), src, dst.len());
        assert_eq!(n, usize::MAX);
        assert_eq!(errno_value(), libc::EILSEQ);

        free(src.cast());
    }
}

// ── mbsinit / mbrlen ────────────────────────────────────────────────────────

#[test]
fn mbsinit_returns_nonzero_for_null() {
    assert_ne!(unsafe { mbsinit(std::ptr::null()) }, 0);
}

#[test]
fn mbsinit_returns_nonzero_for_initial_state() {
    let state = [0u8; 64]; // Zero-initialized mbstate_t
    assert_ne!(unsafe { mbsinit(state.as_ptr().cast()) }, 0);
}

#[test]
fn mbrlen_measures_multibyte() {
    let _utf8 = utf8_locale();
    let ascii = *b"X";
    let n = unsafe { mbrlen(ascii.as_ptr() as *const c_char, 1, std::ptr::null_mut()) };
    assert_eq!(n, 1);

    let utf8 = [0xC3u8, 0xA9]; // é
    let n = unsafe { mbrlen(utf8.as_ptr() as *const c_char, 2, std::ptr::null_mut()) };
    assert_eq!(n, 2);
}

// ── mbsnrtowcs / wcsnrtombs ────────────────────────────────────────────────

#[test]
fn mbsnrtowcs_converts_bounded() {
    let src_bytes = b"AB\0";
    let mut src_ptr: *const c_char = src_bytes.as_ptr() as *const c_char;
    let mut dst = [0i32; 8];
    let written = unsafe {
        mbsnrtowcs(
            dst.as_mut_ptr(),
            &mut src_ptr as *mut *const c_char,
            3, // nms: max bytes to examine
            dst.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(written, 2);
    assert!(src_ptr.is_null()); // Consumed entire string
    assert_eq!(dst[0], b'A' as i32);
    assert_eq!(dst[1], b'B' as i32);
}

#[test]
fn wcsnrtombs_converts_bounded() {
    let src_wcs: [libc::wchar_t; 3] = [b'A' as libc::wchar_t, b'B' as libc::wchar_t, 0];
    let mut src_ptr: *const libc::wchar_t = src_wcs.as_ptr();
    let mut dst = [0i8; 8];
    // nwc=3 allows processing through the NUL terminator
    let written = unsafe {
        wcsnrtombs(
            dst.as_mut_ptr(),
            &mut src_ptr,
            3,
            dst.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(written, 2);
    assert!(src_ptr.is_null()); // NUL was reached → src set to null
    assert_eq!(dst[0] as u8, b'A');
    assert_eq!(dst[1] as u8, b'B');
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn wcsnrtombs_rejects_tracked_source_shorter_than_nwc() {
    unsafe {
        let src = malloc_unterminated_wide(&[b'A' as u32, b'B' as u32]);
        let mut src_ptr = src.cast::<libc::wchar_t>() as *const libc::wchar_t;
        let mut dst = [0_i8; 8];

        set_errno(0);
        let written = wcsnrtombs(
            dst.as_mut_ptr(),
            &mut src_ptr,
            3,
            dst.len(),
            std::ptr::null_mut(),
        );
        assert_eq!(written, usize::MAX);
        assert_eq!(errno_value(), libc::EILSEQ);

        free(src.cast());
    }
}

// ── basename / dirname ──────────────────────────────────────────────────────

#[test]
fn basename_extracts_filename() {
    let mut path = b"/usr/lib/libm.so\0".to_vec();
    let result = unsafe { basename(path.as_mut_ptr() as *mut c_char) };
    assert!(!result.is_null());
    let name = unsafe { CStr::from_ptr(result) }.to_bytes();
    assert_eq!(name, b"libm.so");
}

#[test]
fn basename_handles_trailing_slash() {
    let mut path = b"/usr/lib/\0".to_vec();
    let result = unsafe { basename(path.as_mut_ptr() as *mut c_char) };
    assert!(!result.is_null());
    let name = unsafe { CStr::from_ptr(result) }.to_bytes();
    // The bare `basename` symbol is the GNU variant (POSIX is __xpg_basename):
    // it returns the component after the LAST '/', so a trailing-slash path
    // yields "" — it does NOT strip trailing slashes.
    assert_eq!(name, b"");
}

#[test]
fn dirname_extracts_directory() {
    let mut path = b"/usr/lib/libm.so\0".to_vec();
    let result = unsafe { dirname(path.as_mut_ptr() as *mut c_char) };
    assert!(!result.is_null());
    let dir = unsafe { CStr::from_ptr(result) }.to_bytes();
    assert_eq!(dir, b"/usr/lib");
}

#[test]
fn dirname_root_path() {
    let mut path = b"/foo\0".to_vec();
    let result = unsafe { dirname(path.as_mut_ptr() as *mut c_char) };
    assert!(!result.is_null());
    let dir = unsafe { CStr::from_ptr(result) }.to_bytes();
    assert_eq!(dir, b"/");
}

#[test]
fn dirname_no_slash() {
    let mut path = b"file.txt\0".to_vec();
    let result = unsafe { dirname(path.as_mut_ptr() as *mut c_char) };
    assert!(!result.is_null());
    let dir = unsafe { CStr::from_ptr(result) }.to_bytes();
    assert_eq!(dir, b".");
}

// ── swprintf / swscanf ─────────────────────────────────────────────────────

#[test]
fn swprintf_formats_integer() {
    let mut buf = [0u32; 32];
    // Format: "%d"
    let fmt = [b'%' as u32, b'd' as u32, 0];
    let n = unsafe {
        swprintf(
            buf.as_mut_ptr() as *mut libc::wchar_t,
            32,
            fmt.as_ptr() as *const libc::wchar_t,
            42i32,
        )
    };
    assert!(n > 0);
    let rendered: Vec<u8> = buf[..n as usize].iter().map(|&c| c as u8).collect();
    assert_eq!(rendered, b"42");
}

#[test]
fn swprintf_formats_string() {
    let mut buf = [0u32; 32];
    // Format: "%s" (narrow string)
    let fmt = [b'%' as u32, b's' as u32, 0];
    let n = unsafe {
        swprintf(
            buf.as_mut_ptr() as *mut libc::wchar_t,
            32,
            fmt.as_ptr() as *const libc::wchar_t,
            c"hi".as_ptr(),
        )
    };
    assert!(n > 0);
    let rendered: Vec<u8> = buf[..n as usize].iter().map(|&c| c as u8).collect();
    assert_eq!(rendered, b"hi");
}

#[test]
fn swscanf_parses_integer() {
    let input = wstr(b"42 hello");
    let mut val: c_int = 0;
    let n = unsafe {
        swscanf(
            input.as_ptr() as *const libc::wchar_t,
            wstr(b"%d").as_ptr() as *const libc::wchar_t,
            &mut val as *mut c_int,
        )
    };
    assert_eq!(n, 1);
    assert_eq!(val, 42);
}

#[test]
fn wide_vscanf_null_va_list_fails_closed() {
    let input = wstr(b"42");
    let fmt = wstr(b"%d");

    let rc = unsafe {
        vswscanf(
            input.as_ptr() as *const libc::wchar_t,
            fmt.as_ptr() as *const libc::wchar_t,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, libc::EOF);

    let rc = unsafe { vwscanf(fmt.as_ptr() as *const libc::wchar_t, std::ptr::null_mut()) };
    assert_eq!(rc, libc::EOF);

    let rc = unsafe {
        vfwscanf(
            std::ptr::null_mut(),
            fmt.as_ptr() as *const libc::wchar_t,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, libc::EOF);
}

// ── c32rtomb / mbrtoc32 ────────────────────────────────────────────────────

#[test]
fn c32rtomb_encodes_ascii() {
    let mut buf = [0i8; 4];
    let n = unsafe { c32rtomb(buf.as_mut_ptr(), b'A' as u32, std::ptr::null_mut()) };
    assert_eq!(n, 1);
    assert_eq!(buf[0] as u8, b'A');
}

#[test]
fn c32rtomb_encodes_multibyte() {
    let _utf8 = utf8_locale();
    let mut buf = [0i8; 4];
    let n = unsafe { c32rtomb(buf.as_mut_ptr(), 'é' as u32, std::ptr::null_mut()) };
    assert_eq!(n, 2);
    assert_eq!(buf[0] as u8, 0xC3);
    assert_eq!(buf[1] as u8, 0xA9);
}

#[test]
fn mbrtoc32_decodes_ascii() {
    let mut c32: u32 = 0;
    let input = [b'X' as i8];
    let n = unsafe { mbrtoc32(&mut c32, input.as_ptr(), 1, std::ptr::null_mut()) };
    assert_eq!(n, 1);
    assert_eq!(c32, b'X' as u32);
}

#[test]
fn mbrtoc32_decodes_multibyte() {
    let _utf8 = utf8_locale();
    let mut c32: u32 = 0;
    let input = [0xC3u8 as i8, 0xA9u8 as i8]; // é
    let n = unsafe { mbrtoc32(&mut c32, input.as_ptr(), 2, std::ptr::null_mut()) };
    assert_eq!(n, 2);
    assert_eq!(c32, 'é' as u32);
}

// ── c16rtomb / mbrtoc16 ────────────────────────────────────────────────────

#[test]
fn c16rtomb_encodes_bmp_char() {
    let mut buf = [0i8; 4];
    let n = unsafe { c16rtomb(buf.as_mut_ptr(), b'A' as u16, std::ptr::null_mut()) };
    assert_eq!(n, 1);
    assert_eq!(buf[0] as u8, b'A');
}

#[test]
fn mbrtoc16_decodes_ascii() {
    let mut c16: u16 = 0;
    let input = [b'X' as i8];
    let n = unsafe { mbrtoc16(&mut c16, input.as_ptr(), 1, std::ptr::null_mut()) };
    assert_eq!(n, 1);
    assert_eq!(c16, b'X' as u16);
}

// ── Locale _l conversion variants ───────────────────────────────────────────

#[test]
fn wcsto_l_c_locale_variants_match_base() {
    let signed = wstr(b"-123x");
    let unsigned = wstr(b"255z");
    let mut end: *mut libc::wchar_t = std::ptr::null_mut();
    // SAFETY: *_l conversions require a live locale_t, not a null placeholder.
    let loc = unsafe {
        frankenlibc_abi::locale_abi::newlocale(
            libc::LC_ALL_MASK,
            c"C".as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert!(!loc.is_null());

    let long = unsafe { wcstol_l(signed.as_ptr() as *const libc::wchar_t, &mut end, 10, loc) };
    assert_eq!(long, -123);
    assert_eq!(
        unsafe { end.offset_from(signed.as_ptr() as *mut libc::wchar_t) },
        4
    );

    end = std::ptr::null_mut();
    let long_long =
        unsafe { wcstoll_l(signed.as_ptr() as *const libc::wchar_t, &mut end, 10, loc) };
    assert_eq!(long_long, -123);
    assert_eq!(
        unsafe { end.offset_from(signed.as_ptr() as *mut libc::wchar_t) },
        4
    );

    end = std::ptr::null_mut();
    let ulong = unsafe { wcstoul_l(unsigned.as_ptr() as *const libc::wchar_t, &mut end, 10, loc) };
    assert_eq!(ulong, 255);
    assert_eq!(
        unsafe { end.offset_from(unsigned.as_ptr() as *mut libc::wchar_t) },
        3
    );

    end = std::ptr::null_mut();
    let ulong_long =
        unsafe { wcstoull_l(unsigned.as_ptr() as *const libc::wchar_t, &mut end, 10, loc) };
    assert_eq!(ulong_long, 255);
    assert_eq!(
        unsafe { end.offset_from(unsigned.as_ptr() as *mut libc::wchar_t) },
        3
    );
    // SAFETY: all conversions have completed and this test owns the handle.
    unsafe { frankenlibc_abi::locale_abi::freelocale(loc) };
}

#[test]
fn wcstod_l_c_locale_matches_base() {
    let input = wstr(b"2.5");
    let mut end: *mut libc::wchar_t = std::ptr::null_mut();
    // SAFETY: use the same valid GNU locale contract as the integer family.
    let loc = unsafe {
        frankenlibc_abi::locale_abi::newlocale(
            libc::LC_ALL_MASK,
            c"C".as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert!(!loc.is_null());
    let v = unsafe { wcstod_l(input.as_ptr() as *const libc::wchar_t, &mut end, loc) };
    assert!((v - 2.5).abs() < 1e-10);
    // SAFETY: the conversion has completed and this test owns the handle.
    unsafe { frankenlibc_abi::locale_abi::freelocale(loc) };
}

// ── Existing tests (preserved) ──────────────────────────────────────────────

#[test]
fn mkstemp_creates_unique_file_and_rewrites_template() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let mut template = format!("/tmp/frankenlibc-wchar-mkstemp-{stamp}-XXXXXX\0").into_bytes();

    let fd = unsafe { mkstemp(template.as_mut_ptr().cast()) };
    assert!(fd >= 0);

    let path = unsafe { CStr::from_ptr(template.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();
    assert!(!path.ends_with("XXXXXX"));

    assert_eq!(unsafe { libc::close(fd) }, 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn realpath_resolves_existing_path_into_caller_buffer() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let base = std::env::temp_dir().join(format!("frankenlibc-realpath-{stamp}"));
    let nested = base.join("sub");
    std::fs::create_dir_all(&nested).expect("create temp test dir");
    let file = nested.join("x.txt");
    std::fs::write(&file, b"ok").expect("write temp test file");

    let input = std::ffi::CString::new(format!("{}/sub/../sub/x.txt", base.to_string_lossy()))
        .expect("path should not contain NUL");
    let expected = std::fs::canonicalize(&file).expect("canonicalize expected file");

    let mut out = vec![0_i8; 4096];
    let result = unsafe { realpath(input.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(result, out.as_mut_ptr());
    assert!(!result.is_null());

    let resolved = unsafe { CStr::from_ptr(result) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(resolved, expected.to_string_lossy());

    let _ = std::fs::remove_file(file);
    let _ = std::fs::remove_dir(nested);
    let _ = std::fs::remove_dir(base);
}

#[test]
fn wcsnlen_stops_at_nul_and_bound() {
    let value: [libc::wchar_t; 4] = [
        b'a' as libc::wchar_t,
        b'b' as libc::wchar_t,
        0,
        b'c' as libc::wchar_t,
    ];

    assert_eq!(unsafe { wcsnlen(value.as_ptr(), 8) }, 2);
    assert_eq!(unsafe { wcsnlen(value.as_ptr(), 1) }, 1);
}

#[test]
fn wcswidth_reports_width_and_nonprintable() {
    let _utf8 = utf8_locale();
    let printable: [libc::wchar_t; 3] = [b'A' as libc::wchar_t, 0x754c_i32, 0];
    let non_printable: [libc::wchar_t; 2] = [0x07, 0];

    assert_eq!(unsafe { wcswidth(printable.as_ptr(), 8) }, 3);
    assert_eq!(unsafe { wcswidth(printable.as_ptr(), 1) }, 1);
    assert_eq!(unsafe { wcswidth(non_printable.as_ptr(), 8) }, -1);
}

#[test]
fn wctob_and_btowc_roundtrip_ascii_only() {
    assert_eq!(unsafe { wctob(b'Z' as u32) }, b'Z' as i32);
    assert_eq!(unsafe { wctob(0x80) }, libc::EOF);
    assert_eq!(unsafe { btowc(libc::EOF) }, u32::MAX);
    assert_eq!(unsafe { btowc(b'Z' as i32) }, b'Z' as u32);
    assert_eq!(unsafe { btowc(0x80) }, u32::MAX);
}

#[test]
fn wcrtomb_encodes_ascii_and_reports_invalid() {
    let mut out = [0_i8; 4];

    let n = unsafe {
        wcrtomb(
            out.as_mut_ptr(),
            b'A' as libc::wchar_t,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(n, 1);
    assert_eq!(out[0] as u8, b'A');

    // Reject a genuinely invalid wide char. NOTE: U+110000 is NOT a valid
    // rejection target here — this host's glibc UTF-8 encoder is RFC 2279
    // (MB_CUR_MAX 6) and encodes code points up to U+7FFFFFFF, so it returns a
    // 4-byte sequence for U+110000 (matched by wchar_core::wctomb and verified
    // in conformance_diff_mbtowc_wctomb.rs). A UTF-16 surrogate, however, is
    // invalid under both RFC 2279 and RFC 3629 and is rejected by both.
    set_errno(0);
    let invalid = unsafe { wcrtomb(out.as_mut_ptr(), 0xD800_i32, std::ptr::null_mut()) };
    assert_eq!(invalid, usize::MAX);
    assert_eq!(errno_value(), libc::EILSEQ);
}

#[test]
fn mbrtowc_handles_success_incomplete_and_invalid() {
    let _utf8 = utf8_locale();
    let mut wc: libc::wchar_t = 0;
    let ascii = [b'Z' as i8];

    let ok = unsafe {
        mbrtowc(
            &mut wc as *mut libc::wchar_t,
            ascii.as_ptr(),
            ascii.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(ok, 1);
    assert_eq!(wc as u32, b'Z' as u32);

    let incomplete = [0xC3_u8 as i8];
    let short = unsafe {
        mbrtowc(
            &mut wc as *mut libc::wchar_t,
            incomplete.as_ptr(),
            incomplete.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(short, usize::MAX - 1);

    let invalid = [0xFF_u8 as i8];
    set_errno(0);
    let bad = unsafe {
        mbrtowc(
            &mut wc as *mut libc::wchar_t,
            invalid.as_ptr(),
            invalid.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(bad, usize::MAX);
    assert_eq!(errno_value(), libc::EILSEQ);
}

#[test]
fn mbsrtowcs_converts_and_updates_source_pointer() {
    let _utf8 = utf8_locale();
    let src = [0xC3_u8 as i8, 0xA9_u8 as i8, b'A' as i8, 0];
    let mut src_ptr = src.as_ptr();
    let mut dst = [0_i32; 8];

    let written = unsafe {
        mbsrtowcs(
            dst.as_mut_ptr(),
            &mut src_ptr as *mut *const i8,
            dst.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(written, 2);
    assert!(src_ptr.is_null());
    assert_eq!(dst[0] as u32, 'é' as u32);
    assert_eq!(dst[1] as u32, 'A' as u32);
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn mbsrtowcs_rejects_unterminated_known_input() {
    unsafe {
        let src = malloc(2).cast::<i8>();
        assert!(!src.is_null());
        std::ptr::copy_nonoverlapping(b"AZ".as_ptr().cast::<i8>(), src, 2);

        let mut src_ptr = src as *const i8;
        let mut dst = [0_i32; 4];
        set_errno(0);
        let written = mbsrtowcs(
            dst.as_mut_ptr(),
            &mut src_ptr as *mut *const i8,
            dst.len(),
            std::ptr::null_mut(),
        );
        assert_eq!(written, usize::MAX);
        assert_eq!(errno_value(), libc::EILSEQ);
        assert_eq!(src_ptr, src as *const i8);

        free(src.cast());
    }
}

#[test]
fn wcsrtombs_converts_and_updates_source_pointer() {
    let _utf8 = utf8_locale();
    let src = [b'A' as i32, 0x754c_i32, 0];
    let mut src_ptr = src.as_ptr();
    let mut dst = [0_i8; 16];

    let written = unsafe {
        wcsrtombs(
            dst.as_mut_ptr(),
            &mut src_ptr as *mut *const i32,
            dst.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(written, 4);
    assert!(src_ptr.is_null());
    assert_eq!(dst[0] as u8, b'A');
    assert_eq!(dst[1] as u8, 0xE7);
    assert_eq!(dst[2] as u8, 0x95);
    assert_eq!(dst[3] as u8, 0x8C);
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn wcsrtombs_rejects_tracked_unterminated_wide_input() {
    unsafe {
        let src = malloc_unterminated_wide(&[b'A' as u32, b'B' as u32]);
        let mut src_ptr = src.cast::<libc::wchar_t>() as *const libc::wchar_t;
        let original = src_ptr;
        let mut dst = [0_i8; 8];

        set_errno(0);
        let written = wcsrtombs(
            dst.as_mut_ptr(),
            &mut src_ptr,
            dst.len(),
            std::ptr::null_mut(),
        );
        assert_eq!(written, usize::MAX);
        assert_eq!(errno_value(), libc::EILSEQ);
        assert_eq!(src_ptr, original);

        free(src.cast());
    }
}

#[test]
fn wcstol_parses_and_updates_endptr() {
    let input: [libc::wchar_t; 6] = [
        b' ' as libc::wchar_t,
        b'-' as libc::wchar_t,
        b'1' as libc::wchar_t,
        b'2' as libc::wchar_t,
        b'x' as libc::wchar_t,
        0,
    ];
    let mut end: *mut libc::wchar_t = std::ptr::null_mut();

    let value = unsafe { wcstol(input.as_ptr(), &mut end as *mut *mut libc::wchar_t, 10) };
    assert_eq!(value, -12);
    assert_eq!(
        unsafe { end.offset_from(input.as_ptr() as *mut libc::wchar_t) },
        4
    );

    set_errno(0);
    // glibc validates the base before any parsing and leaves *endptr UNTOUCHED
    // on an invalid base (it never writes it) — it does NOT set it to nptr.
    let sentinel = 0xdead_beef_usize as *mut libc::wchar_t;
    end = sentinel;
    let invalid_base = unsafe { wcstol(input.as_ptr(), &mut end as *mut *mut libc::wchar_t, 1) };
    assert_eq!(invalid_base, 0);
    assert_eq!(errno_value(), libc::EINVAL);
    assert_eq!(
        end, sentinel,
        "endptr must be left untouched on invalid base"
    );
}

#[test]
fn wcstoul_reports_overflow_and_aliases_follow() {
    let digits = "18446744073709551616";
    let mut wide: Vec<libc::wchar_t> = digits.bytes().map(|b| b as libc::wchar_t).collect();
    wide.push(0);

    let mut end: *mut libc::wchar_t = std::ptr::null_mut();
    set_errno(0);
    let value = unsafe { wcstoul(wide.as_ptr(), &mut end as *mut *mut libc::wchar_t, 10) };
    assert_eq!(value as u64, u64::MAX);
    assert_eq!(errno_value(), libc::ERANGE);
    assert_eq!(
        unsafe { end.offset_from(wide.as_ptr() as *mut libc::wchar_t) },
        digits.len() as isize
    );

    end = std::ptr::null_mut();
    set_errno(0);
    let alias = unsafe { wcstoull(wide.as_ptr(), &mut end as *mut *mut libc::wchar_t, 10) };
    assert_eq!(alias, u64::MAX);
    assert_eq!(errno_value(), libc::ERANGE);
}

#[test]
fn wcstod_family_parses_ascii_and_updates_endptr() {
    let input: [libc::wchar_t; 6] = [
        b'1' as libc::wchar_t,
        b'2' as libc::wchar_t,
        b'.' as libc::wchar_t,
        b'5' as libc::wchar_t,
        b'Z' as libc::wchar_t,
        0,
    ];
    let mut end: *mut libc::wchar_t = std::ptr::null_mut();

    let d = unsafe { wcstod(input.as_ptr(), &mut end as *mut *mut libc::wchar_t) };
    assert!((d - 12.5).abs() < 1e-10);
    assert_eq!(
        unsafe { end.offset_from(input.as_ptr() as *mut libc::wchar_t) },
        4
    );

    end = std::ptr::null_mut();
    let f = unsafe { wcstof(input.as_ptr(), &mut end as *mut *mut libc::wchar_t) };
    assert!((f - 12.5_f32).abs() < 1e-5);
    assert_eq!(
        unsafe { end.offset_from(input.as_ptr() as *mut libc::wchar_t) },
        4
    );

    // `wcstold` is now a naked shim returning in ST(0), which Rust has no type
    // for, so the value is checked through `wcstold_into` — the same path minus
    // the one `fld` that hands the result to a C caller. 12.5 is exponent field
    // 0x4002 with significand 0xc800000000000000, as glibc's own wcstold
    // produces.
    end = std::ptr::null_mut();
    let mut ld_bytes = [0u8; 10];
    unsafe {
        wcstold_into(
            input.as_ptr(),
            &mut end as *mut *mut libc::wchar_t,
            ld_bytes.as_mut_ptr(),
        )
    };
    assert_eq!(
        u64::from_le_bytes(ld_bytes[..8].try_into().unwrap()),
        0xc800_0000_0000_0000
    );
    assert_eq!(u16::from_le_bytes([ld_bytes[8], ld_bytes[9]]), 0x4002);

    let halfway = wstr(b"1.0000000596046447753906251");
    end = std::ptr::null_mut();
    let rounded = unsafe {
        wcstof(
            halfway.as_ptr() as *const libc::wchar_t,
            &mut end as *mut *mut libc::wchar_t,
        )
    };
    assert_eq!(rounded.to_bits(), 0x3f80_0001);
    assert_eq!(
        unsafe { end.offset_from(halfway.as_ptr() as *mut libc::wchar_t) },
        27
    );

    let signed: [libc::wchar_t; 4] = [
        b'-' as libc::wchar_t,
        b'7' as libc::wchar_t,
        b'9' as libc::wchar_t,
        0,
    ];
    end = std::ptr::null_mut();
    let ll = unsafe { wcstoll(signed.as_ptr(), &mut end as *mut *mut libc::wchar_t, 10) };
    assert_eq!(ll, -79);
}

#[test]
fn wcscoll_and_wcsxfrm_follow_c_locale_contract() {
    let a: [libc::wchar_t; 3] = [b'a' as libc::wchar_t, b'b' as libc::wchar_t, 0];
    let b: [libc::wchar_t; 3] = [b'a' as libc::wchar_t, b'c' as libc::wchar_t, 0];

    assert!(unsafe { wcscoll(a.as_ptr(), b.as_ptr()) } < 0);
    assert!(unsafe { wcscoll(b.as_ptr(), a.as_ptr()) } > 0);
    assert_eq!(unsafe { wcscoll(a.as_ptr(), a.as_ptr()) }, 0);

    let src: [libc::wchar_t; 4] = [
        b'a' as libc::wchar_t,
        b'b' as libc::wchar_t,
        b'c' as libc::wchar_t,
        0,
    ];
    let mut dst = [0_i32; 2];
    let needed = unsafe { wcsxfrm(dst.as_mut_ptr(), src.as_ptr(), dst.len()) };
    // glibc fills min(n, src_len+1) chars and only NUL-terminates if it fits;
    // here n(2) <= src_len(3), so both transform chars are written and the
    // prefix is left UNTERMINATED (no room for a NUL).
    assert_eq!(needed, 3);
    assert_eq!(dst[0] as u8, b'a');
    assert_eq!(dst[1] as u8, b'b');
}

#[test]
fn wcsftime_formats_via_native_bridge() {
    let mut out = [0_i32; 32];
    let fmt: [libc::wchar_t; 9] = [
        b'%' as libc::wchar_t,
        b'Y' as libc::wchar_t,
        b'-' as libc::wchar_t,
        b'%' as libc::wchar_t,
        b'm' as libc::wchar_t,
        b'-' as libc::wchar_t,
        b'%' as libc::wchar_t,
        b'd' as libc::wchar_t,
        0,
    ];

    let tm = libc::tm {
        tm_sec: 5,
        tm_min: 4,
        tm_hour: 3,
        tm_mday: 2,
        tm_mon: 0,
        tm_year: 126,
        tm_wday: 5,
        tm_yday: 1,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    };

    let written = unsafe {
        wcsftime(
            out.as_mut_ptr(),
            out.len(),
            fmt.as_ptr(),
            &tm as *const libc::tm as *const c_void,
        )
    };
    assert_eq!(written, 10);
    let rendered: Vec<u32> = out[..written].iter().map(|&ch| ch as u32).collect();
    assert_eq!(
        rendered,
        "2026-01-02".bytes().map(u32::from).collect::<Vec<_>>()
    );
}

#[test]
fn wcsftime_exact_iso_alias_uses_fixed_width_contract() {
    let fmt: [libc::wchar_t; 6] = [
        b'%' as libc::wchar_t,
        b'F' as libc::wchar_t,
        b'T' as libc::wchar_t,
        b'%' as libc::wchar_t,
        b'T' as libc::wchar_t,
        0,
    ];
    let tm = libc::tm {
        tm_sec: 5,
        tm_min: 4,
        tm_hour: 3,
        tm_mday: 2,
        tm_mon: 0,
        tm_year: 126,
        tm_wday: 5,
        tm_yday: 1,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    };

    let mut exact_fit = [b'?' as libc::wchar_t; 19];
    assert_eq!(
        unsafe {
            wcsftime(
                exact_fit.as_mut_ptr(),
                exact_fit.len(),
                fmt.as_ptr(),
                &tm as *const libc::tm as *const c_void,
            )
        },
        0
    );

    let mut out = [0_i32; 20];
    let written = unsafe {
        wcsftime(
            out.as_mut_ptr(),
            out.len(),
            fmt.as_ptr(),
            &tm as *const libc::tm as *const c_void,
        )
    };
    assert_eq!(written, 19);
    let rendered: Vec<u32> = out[..written].iter().map(|&ch| ch as u32).collect();
    assert_eq!(
        rendered,
        "2026-01-02T03:04:05"
            .bytes()
            .map(u32::from)
            .collect::<Vec<_>>()
    );
    assert_eq!(out[written], 0);
}

#[test]
fn wcsftime_l_null_locale_matches_base() {
    let mut out = [0_i32; 32];
    let fmt: [libc::wchar_t; 9] = [
        b'%' as libc::wchar_t,
        b'Y' as libc::wchar_t,
        b'-' as libc::wchar_t,
        b'%' as libc::wchar_t,
        b'm' as libc::wchar_t,
        b'-' as libc::wchar_t,
        b'%' as libc::wchar_t,
        b'd' as libc::wchar_t,
        0,
    ];

    let tm = libc::tm {
        tm_sec: 5,
        tm_min: 4,
        tm_hour: 3,
        tm_mday: 2,
        tm_mon: 0,
        tm_year: 126,
        tm_wday: 5,
        tm_yday: 1,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    };

    let written = unsafe {
        wcsftime_l(
            out.as_mut_ptr(),
            out.len(),
            fmt.as_ptr(),
            &tm as *const libc::tm as *const c_void,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(written, 10);
    let rendered: Vec<u32> = out[..written].iter().map(|&ch| ch as u32).collect();
    assert_eq!(
        rendered,
        "2026-01-02".bytes().map(u32::from).collect::<Vec<_>>()
    );
}

#[test]
fn wide_stream_char_roundtrip_and_pushback() {
    let _utf8 = utf8_locale();
    let stream = unsafe { frankenlibc_abi::stdio_abi::tmpfile() };
    assert!(!stream.is_null());

    assert_eq!(unsafe { fputwc('é' as u32, stream) }, 'é' as u32);
    assert_eq!(unsafe { fputwc('A' as u32, stream) }, 'A' as u32);
    assert_eq!(
        unsafe { frankenlibc_abi::stdio_abi::fseek(stream, 0, libc::SEEK_SET) },
        0
    );

    assert_eq!(unsafe { fgetwc(stream) }, 'é' as u32);
    assert_eq!(unsafe { fgetwc(stream) }, 'A' as u32);
    assert_eq!(unsafe { fgetwc(stream) }, u32::MAX); // WEOF

    assert_eq!(
        unsafe { frankenlibc_abi::stdio_abi::fseek(stream, 0, libc::SEEK_SET) },
        0
    );
    assert_eq!(unsafe { ungetwc('Z' as u32, stream) }, 'Z' as u32);
    assert_eq!(unsafe { fgetwc(stream) }, 'Z' as u32);
    assert_eq!(unsafe { fgetwc(stream) }, 'é' as u32);

    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(stream) }, 0);
}

#[test]
fn wide_stream_getwc_putwc_aliases_roundtrip() {
    let stream = unsafe { frankenlibc_abi::stdio_abi::tmpfile() };
    assert!(!stream.is_null());

    assert_eq!(
        unsafe { putwc('R' as libc::wchar_t, stream.cast::<libc::FILE>()) },
        'R' as u32
    );
    assert_eq!(unsafe { putwc_unlocked('S' as u32, stream) }, 'S' as u32);
    assert_eq!(
        unsafe { frankenlibc_abi::stdio_abi::fseek(stream, 0, libc::SEEK_SET) },
        0
    );

    assert_eq!(unsafe { getwc(stream.cast::<libc::FILE>()) }, 'R' as u32);
    assert_eq!(
        unsafe { getwc_unlocked(stream.cast::<libc::FILE>()) },
        'S' as u32
    );
    assert_eq!(
        unsafe { getwc_unlocked(stream.cast::<libc::FILE>()) },
        u32::MAX
    );

    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(stream) }, 0);
}

#[test]
fn wide_stdio_unlocked_aliases_use_redirected_globals() {
    let in_stream = unsafe { frankenlibc_abi::stdio_abi::tmpfile() };
    let out_stream = unsafe { frankenlibc_abi::stdio_abi::tmpfile() };
    assert!(!in_stream.is_null());
    assert!(!out_stream.is_null());

    assert_eq!(unsafe { fputwc('Q' as u32, in_stream) }, 'Q' as u32);
    assert_eq!(
        unsafe { frankenlibc_abi::stdio_abi::fseek(in_stream, 0, libc::SEEK_SET) },
        0
    );

    {
        let _stdio = unsafe { StdioGlobalStreamGuard::install(in_stream, out_stream) };
        assert_eq!(unsafe { getwchar_unlocked() }, 'Q' as u32);
        assert_eq!(unsafe { putwchar_unlocked('Z' as u32) }, 'Z' as u32);
    }

    assert_eq!(
        unsafe { frankenlibc_abi::stdio_abi::fseek(out_stream, 0, libc::SEEK_SET) },
        0
    );
    assert_eq!(unsafe { fgetwc(out_stream) }, 'Z' as u32);

    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(in_stream) }, 0);
    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(out_stream) }, 0);
}

#[test]
fn wide_stream_string_io_handles_newline_splitting() {
    let stream = unsafe { frankenlibc_abi::stdio_abi::tmpfile() };
    assert!(!stream.is_null());

    let src: [libc::wchar_t; 9] = [
        b'h' as libc::wchar_t,
        b'i' as libc::wchar_t,
        b'\n' as libc::wchar_t,
        b't' as libc::wchar_t,
        b'h' as libc::wchar_t,
        b'e' as libc::wchar_t,
        b'r' as libc::wchar_t,
        b'e' as libc::wchar_t,
        0,
    ];

    assert_eq!(unsafe { fputws(src.as_ptr(), stream) }, 0);
    assert_eq!(
        unsafe { frankenlibc_abi::stdio_abi::fseek(stream, 0, libc::SEEK_SET) },
        0
    );

    let mut buf = [0_i32; 16];
    let first = unsafe { fgetws(buf.as_mut_ptr(), buf.len() as i32, stream) };
    assert!(!first.is_null());
    let first_len = buf.iter().position(|&ch| ch == 0).unwrap_or(buf.len());
    let first_text: Vec<u8> = buf[..first_len].iter().map(|&ch| ch as u8).collect();
    assert_eq!(first_text, b"hi\n");

    buf.fill(0);
    let second = unsafe { fgetws(buf.as_mut_ptr(), buf.len() as i32, stream) };
    assert!(!second.is_null());
    let second_len = buf.iter().position(|&ch| ch == 0).unwrap_or(buf.len());
    let second_text: Vec<u8> = buf[..second_len].iter().map(|&ch| ch as u8).collect();
    assert_eq!(second_text, b"there");

    assert!(unsafe { fgetws(buf.as_mut_ptr(), buf.len() as i32, stream) }.is_null());

    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(stream) }, 0);
}

#[test]
fn open_wmemstream_flushes_wide_buffer_and_reports_orientation() {
    let _utf8 = utf8_locale();
    let mut buf: *mut u32 = std::ptr::null_mut();
    let mut size = 0usize;
    let stream = unsafe { open_wmemstream(&mut buf, &mut size) };
    assert!(!stream.is_null());
    assert!(!buf.is_null());
    assert_eq!(size, 0);
    assert!(verify_native_file(stream).is_some());
    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fileno(stream) }, -1);

    assert!(unsafe { fwide(stream, 0) } > 0);
    assert!(unsafe { fwide(stream, -1) } > 0);

    assert_eq!(unsafe { fputwc('é' as u32, stream) }, 'é' as u32);
    assert_eq!(unsafe { fputwc('A' as u32, stream) }, 'A' as u32);
    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fflush(stream) }, 0);

    assert_eq!(size, 2);
    let written = unsafe { std::slice::from_raw_parts(buf, size + 1) };
    assert_eq!(written[0], 'é' as u32);
    assert_eq!(written[1], 'A' as u32);
    assert_eq!(written[2], 0);

    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(stream) }, 0);
    assert!(verify_native_file(stream).is_none());
    assert_eq!(size, 2);
    let written = unsafe { std::slice::from_raw_parts(buf, size + 1) };
    assert_eq!(written[0], 'é' as u32);
    assert_eq!(written[1], 'A' as u32);
    assert_eq!(written[2], 0);

    unsafe { frankenlibc_abi::malloc_abi::free(buf.cast::<c_void>()) };
}

// ---------------------------------------------------------------------------
// fgetwln (NetBSD libutil wide-char line reader)
// ---------------------------------------------------------------------------

#[test]
fn fgetwln_reads_two_lines_then_eof() {
    let stream = unsafe { frankenlibc_abi::stdio_abi::tmpfile() };
    assert!(!stream.is_null());

    let src: [libc::wchar_t; 14] = [
        b'h' as libc::wchar_t,
        b'i' as libc::wchar_t,
        b'\n' as libc::wchar_t,
        b'b' as libc::wchar_t,
        b'y' as libc::wchar_t,
        b'e' as libc::wchar_t,
        b'\n' as libc::wchar_t,
        b'l' as libc::wchar_t,
        b'a' as libc::wchar_t,
        b's' as libc::wchar_t,
        b't' as libc::wchar_t,
        0,
        0,
        0,
    ];
    assert_eq!(unsafe { fputws(src.as_ptr(), stream) }, 0);
    assert_eq!(
        unsafe { frankenlibc_abi::stdio_abi::fseek(stream, 0, libc::SEEK_SET) },
        0
    );

    // Line 1: "hi\n"
    let mut len: usize = 0;
    let p = unsafe { fgetwln(stream, &mut len) };
    assert!(!p.is_null());
    assert_eq!(len, 3);
    let l1 = unsafe { std::slice::from_raw_parts(p, len) };
    assert_eq!(l1[0], b'h' as libc::wchar_t);
    assert_eq!(l1[1], b'i' as libc::wchar_t);
    assert_eq!(l1[2], b'\n' as libc::wchar_t);

    // Line 2: "bye\n"
    let p2 = unsafe { fgetwln(stream, &mut len) };
    assert!(!p2.is_null());
    assert_eq!(len, 4);
    let l2 = unsafe { std::slice::from_raw_parts(p2, len) };
    assert_eq!(l2[0], b'b' as libc::wchar_t);
    assert_eq!(l2[3], b'\n' as libc::wchar_t);

    // Line 3: "last" (no trailing newline)
    let p3 = unsafe { fgetwln(stream, &mut len) };
    assert!(!p3.is_null());
    assert_eq!(len, 4);
    let l3 = unsafe { std::slice::from_raw_parts(p3, len) };
    assert_eq!(l3[0], b'l' as libc::wchar_t);
    assert_eq!(l3[3], b't' as libc::wchar_t);

    // EOF: NULL + len cleared.
    len = 999;
    let p4 = unsafe { fgetwln(stream, &mut len) };
    assert!(p4.is_null());
    assert_eq!(len, 0);

    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(stream) }, 0);
}

#[test]
fn fgetwln_handles_null_stream() {
    let mut len: usize = 999;
    let p = unsafe { fgetwln(std::ptr::null_mut(), &mut len) };
    assert!(p.is_null());
    assert_eq!(len, 0);
}

#[test]
fn fgetwln_accepts_null_lenp() {
    let stream = unsafe { frankenlibc_abi::stdio_abi::tmpfile() };
    assert!(!stream.is_null());

    let src: [libc::wchar_t; 5] = [
        b'h' as libc::wchar_t,
        b'i' as libc::wchar_t,
        b'\n' as libc::wchar_t,
        0,
        0,
    ];
    assert_eq!(unsafe { fputws(src.as_ptr(), stream) }, 0);
    assert_eq!(
        unsafe { frankenlibc_abi::stdio_abi::fseek(stream, 0, libc::SEEK_SET) },
        0
    );

    let p = unsafe { fgetwln(stream, std::ptr::null_mut()) };
    assert!(!p.is_null());
    // We can still read the bytes; we just need to know the line ends with \n
    // at index 2 (length = 3, but we can't observe length without lenp).
    let s = unsafe { std::slice::from_raw_parts(p, 3) };
    assert_eq!(s[0], b'h' as libc::wchar_t);
    assert_eq!(s[2], b'\n' as libc::wchar_t);

    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(stream) }, 0);
}

// ---------------------------------------------------------------------------
// bd-xh08pf burn-down: wchar_abi's two inline `#[cfg(test)]` tests never
// compiled — lib.rs declares the module `#[cfg(not(test))]`, so the two cfgs are
// mutually exclusive and they built in neither configuration.
//
// They exercised `wide_to_narrow` / `wide_to_narrow_pooled` / `WPRINTF_FORMAT_BUF`
// directly, all module-private. Reconstructed here through `swprintf`, which is
// the caller that drives that conversion: the wide FORMAT string is what gets
// converted to narrow, so a format carrying an invalid codepoint, and a second
// call reusing the pooled buffer, reach the same code the originals did.
//
// The capacity assertion is dropped: buffer retention has no caller-visible
// consequence beyond producing correct output on the next call, which is exactly
// what the reuse test below asserts.
// ---------------------------------------------------------------------------

/// An invalid codepoint in the wide FORMAT renders as U+FFFD.
///
/// Was `pooled_wide_format_preserves_invalid_codepoint_replacement`, which
/// compared the pooled converter against the fresh one on `<U+110000>`.
#[test]
fn swprintf_wide_format_replaces_invalid_codepoint() {
    let _utf8 = utf8_locale();
    // 0x110000 is one past the Unicode maximum, so it is not a scalar value and
    // cannot be written as a Rust char literal — hence the raw array, as the
    // stranded test also built it.
    let fmt = [b'<' as u32, 0x11_0000u32, b'>' as u32, 0];
    let mut buf = [0u32; 32];
    // SAFETY: `fmt` is NUL-terminated and `buf` has room for the rendering.
    let n = unsafe {
        swprintf(
            buf.as_mut_ptr() as *mut libc::wchar_t,
            32,
            fmt.as_ptr() as *const libc::wchar_t,
        )
    };
    assert!(n > 0, "swprintf should render the literal format");
    let rendered: Vec<u32> = buf[..n as usize].to_vec();
    assert_eq!(
        rendered,
        vec![b'<' as u32, 0xFFFD, b'>' as u32],
        "an invalid codepoint in the wide format must become U+FFFD, not be dropped \
         or emitted raw"
    );
}

/// The pooled format buffer must not leak content between calls.
///
/// Was `pooled_wide_format_matches_fresh_converter_and_reuses_capacity`, whose
/// caller-visible half is that a second, SHORTER format renders correctly after
/// a longer one has grown the pool — a stale tail would show up here.
#[test]
fn swprintf_reused_format_buffer_does_not_leak_between_calls() {
    let long_fmt = [
        b'[' as u32,
        b'%' as u32,
        b'd' as u32,
        b'-' as u32,
        b'-' as u32,
        b'-' as u32,
        b'-' as u32,
        b'-' as u32,
        b'-' as u32,
        b'-' as u32,
        b']' as u32,
        0,
    ];
    let mut buf = [0u32; 64];
    // SAFETY: NUL-terminated format, buffer large enough.
    let n = unsafe {
        swprintf(
            buf.as_mut_ptr() as *mut libc::wchar_t,
            64,
            long_fmt.as_ptr() as *const libc::wchar_t,
            7i32,
        )
    };
    assert!(n > 0);
    let first: Vec<u8> = buf[..n as usize].iter().map(|&c| c as u8).collect();
    assert_eq!(first, b"[7-------]");

    // A shorter format immediately after: if the pooled buffer were reused
    // without being truncated, the tail of the previous format would survive.
    let short_fmt = [b'%' as u32, b'd' as u32, 0];
    let mut buf2 = [0u32; 64];
    // SAFETY: as above.
    let n2 = unsafe {
        swprintf(
            buf2.as_mut_ptr() as *mut libc::wchar_t,
            64,
            short_fmt.as_ptr() as *const libc::wchar_t,
            9i32,
        )
    };
    assert!(n2 > 0);
    let second: Vec<u8> = buf2[..n2 as usize].iter().map(|&c| c as u8).collect();
    assert_eq!(
        second, b"9",
        "the reused format buffer must not carry a tail from the previous call"
    );
}

struct GuardedPages {
    base: *mut u8,
    total_len: usize,
    page_size: usize,
}

impl GuardedPages {
    fn new(readable_pages: usize) -> Self {
        // SAFETY: sysconf(_SC_PAGESIZE) is always safe to call.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert!(page_size >= 4096 && page_size.is_power_of_two());
        let total_len = (readable_pages + 1) * page_size;
        // SAFETY: anonymous private mapping with no fixed address.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED, "mmap failed");
        // SAFETY: last page is inside the freshly mapped region.
        let rc = unsafe {
            libc::mprotect(
                base.cast::<u8>().add(readable_pages * page_size).cast(),
                page_size,
                libc::PROT_NONE,
            )
        };
        assert_eq!(rc, 0, "mprotect(PROT_NONE) failed");
        Self {
            base: base.cast::<u8>(),
            total_len,
            page_size,
        }
    }

    fn guard_edge(&self) -> *mut u8 {
        // SAFETY: points to the start of the final PROT_NONE guard page.
        unsafe { self.base.add(self.total_len - self.page_size) }
    }
}

impl Drop for GuardedPages {
    fn drop(&mut self) {
        // SAFETY: `base` and `total_len` came directly from `mmap`.
        unsafe {
            libc::munmap(self.base.cast(), self.total_len);
        }
    }
}

#[test]
fn mbsnrtowcs_stops_before_prot_none_guard_page() {
    let _utf8 = utf8_locale();
    let pages = GuardedPages::new(1);
    let edge = pages.guard_edge();

    // "hi\0" sitting immediately before the PROT_NONE page with nms >> 3.
    unsafe {
        let src_start = edge.sub(3);
        std::ptr::copy_nonoverlapping(b"hi\0".as_ptr(), src_start, 3);

        let mut src_ptr = src_start.cast::<c_char>().cast_const();
        let mut dst = [0 as libc::wchar_t; 16];
        let n = mbsnrtowcs(
            dst.as_mut_ptr(),
            &mut src_ptr,
            100,
            dst.len(),
            std::ptr::null_mut(),
        );
        assert_eq!(n, 2);
        assert!(src_ptr.is_null());
        assert_eq!(dst[0], b'h' as libc::wchar_t);
        assert_eq!(dst[1], b'i' as libc::wchar_t);
        assert_eq!(dst[2], 0);

        let mut count_src = src_start.cast::<c_char>().cast_const();
        let counted = mbsnrtowcs(
            std::ptr::null_mut(),
            &mut count_src,
            100,
            0,
            std::ptr::null_mut(),
        );
        assert_eq!(counted, 2);
        assert_eq!(count_src, src_start.cast::<c_char>().cast_const());

        // Exact-fit write without NUL ("hi" at edge - 2, len = 2, nms = 100).
        let exact_start = edge.sub(2);
        std::ptr::copy_nonoverlapping(b"hi".as_ptr(), exact_start, 2);
        let mut exact_src = exact_start.cast::<c_char>().cast_const();
        let mut exact_dst = [0 as libc::wchar_t; 2];
        let exact_n = mbsnrtowcs(
            exact_dst.as_mut_ptr(),
            &mut exact_src,
            100,
            exact_dst.len(),
            std::ptr::null_mut(),
        );
        assert_eq!(exact_n, 2);
        assert_eq!(exact_src, edge.cast::<c_char>().cast_const());
        assert_eq!(exact_dst, [b'h' as libc::wchar_t, b'i' as libc::wchar_t]);
    }

    // Two readable pages + guard page: 2-byte UTF-8 sequence ("é") straddling
    // the boundary between page 0 and page 1, ending right before page 2 guard.
    let two_pages = GuardedPages::new(2);
    unsafe {
        let mid = two_pages.base.add(two_pages.page_size);
        let straddle_start = mid.sub(2); // 'A', 0xC3 | 0xA9, 'Z', 0
        std::ptr::copy_nonoverlapping([b'A', 0xC3, 0xA9, b'Z', 0].as_ptr(), straddle_start, 5);

        let mut src_ptr = straddle_start.cast::<c_char>().cast_const();
        let mut dst = [0 as libc::wchar_t; 8];
        let n = mbsnrtowcs(
            dst.as_mut_ptr(),
            &mut src_ptr,
            100,
            dst.len(),
            std::ptr::null_mut(),
        );
        assert_eq!(n, 3);
        assert!(src_ptr.is_null());
        assert_eq!(dst[0], b'A' as libc::wchar_t);
        assert_eq!(dst[1], 'é' as libc::wchar_t);
        assert_eq!(dst[2], b'Z' as libc::wchar_t);
        assert_eq!(dst[3], 0);

        let mut count_src = straddle_start.cast::<c_char>().cast_const();
        let counted = mbsnrtowcs(
            std::ptr::null_mut(),
            &mut count_src,
            100,
            0,
            std::ptr::null_mut(),
        );
        assert_eq!(counted, 3);
        assert_eq!(count_src, straddle_start.cast::<c_char>().cast_const());
    }
}

#[test]
fn wcsnrtombs_stops_before_prot_none_guard_page() {
    let _utf8 = utf8_locale();
    let pages = GuardedPages::new(1);
    let edge = pages.guard_edge();

    // L"hi\0" (12 bytes) sitting immediately before the PROT_NONE page with nwc >> 3.
    unsafe {
        let src_start = edge
            .sub(3 * std::mem::size_of::<libc::wchar_t>())
            .cast::<libc::wchar_t>();
        std::ptr::copy_nonoverlapping(
            [b'h' as libc::wchar_t, b'i' as libc::wchar_t, 0].as_ptr(),
            src_start,
            3,
        );

        let mut src_ptr = src_start.cast_const();
        let mut dst = [0 as c_char; 32];
        let n = wcsnrtombs(
            dst.as_mut_ptr(),
            &mut src_ptr,
            100,
            dst.len(),
            std::ptr::null_mut(),
        );
        assert_eq!(n, 2);
        assert!(src_ptr.is_null());
        assert_eq!(dst[0] as u8, b'h');
        assert_eq!(dst[1] as u8, b'i');
        assert_eq!(dst[2] as u8, 0);

        let mut count_src = src_start.cast_const();
        let counted = wcsnrtombs(
            std::ptr::null_mut(),
            &mut count_src,
            100,
            0,
            std::ptr::null_mut(),
        );
        assert_eq!(counted, 2);
        assert_eq!(count_src, src_start.cast_const());

        // Exact-fit write without NUL (L"hi" at edge - 8, len = 2, nwc = 100).
        let exact_start = edge
            .sub(2 * std::mem::size_of::<libc::wchar_t>())
            .cast::<libc::wchar_t>();
        std::ptr::copy_nonoverlapping(
            [b'h' as libc::wchar_t, b'i' as libc::wchar_t].as_ptr(),
            exact_start,
            2,
        );
        let mut exact_src = exact_start.cast_const();
        let mut exact_dst = [0 as c_char; 2];
        let exact_n = wcsnrtombs(
            exact_dst.as_mut_ptr(),
            &mut exact_src,
            100,
            exact_dst.len(),
            std::ptr::null_mut(),
        );
        assert_eq!(exact_n, 2);
        assert_eq!(exact_src, edge.cast::<libc::wchar_t>().cast_const());
        assert_eq!(exact_dst[0] as u8, b'h');
        assert_eq!(exact_dst[1] as u8, b'i');

        // Count-only mode stops at an unrepresentable surrogate before the guard page.
        let bad_start = edge
            .sub(2 * std::mem::size_of::<libc::wchar_t>())
            .cast::<libc::wchar_t>();
        std::ptr::copy_nonoverlapping(
            [b'A' as libc::wchar_t, 0xD800 as libc::wchar_t].as_ptr(),
            bad_start,
            2,
        );
        let mut bad_src = bad_start.cast_const();
        set_errno(0);
        let bad_n = wcsnrtombs(
            std::ptr::null_mut(),
            &mut bad_src,
            100,
            0,
            std::ptr::null_mut(),
        );
        assert_eq!(bad_n, usize::MAX);
        assert_eq!(errno_value(), libc::EILSEQ);
        assert_eq!(bad_src, bad_start.cast_const());
    }

    // Multi-page wide string ending right before a PROT_NONE guard page.
    let two_pages = GuardedPages::new(2);
    unsafe {
        let elem_count = (two_pages.page_size / std::mem::size_of::<libc::wchar_t>()) + 16;
        let src_start = two_pages
            .guard_edge()
            .sub((elem_count + 1) * std::mem::size_of::<libc::wchar_t>())
            .cast::<libc::wchar_t>();
        for i in 0..elem_count {
            *src_start.add(i) = if i == elem_count - 1 {
                'é' as libc::wchar_t
            } else {
                b'x' as libc::wchar_t
            };
        }
        *src_start.add(elem_count) = 0;

        let expected_bytes = (elem_count - 1) + 2;
        let mut count_src = src_start.cast_const();
        let counted = wcsnrtombs(
            std::ptr::null_mut(),
            &mut count_src,
            elem_count + 500,
            0,
            std::ptr::null_mut(),
        );
        assert_eq!(counted, expected_bytes);
        assert_eq!(count_src, src_start.cast_const());

        let mut dst = vec![0 as c_char; expected_bytes + 8];
        let mut write_src = src_start.cast_const();
        let written = wcsnrtombs(
            dst.as_mut_ptr(),
            &mut write_src,
            elem_count + 500,
            dst.len(),
            std::ptr::null_mut(),
        );
        assert_eq!(written, expected_bytes);
        assert!(write_src.is_null());
        assert_eq!(dst[expected_bytes - 2] as u8, 0xC3);
        assert_eq!(dst[expected_bytes - 1] as u8, 0xA9);
        assert_eq!(dst[expected_bytes] as u8, 0);
    }
}
