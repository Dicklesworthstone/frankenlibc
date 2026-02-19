#![cfg(target_os = "linux")]

//! Integration tests for selected `<wchar.h>` ABI entrypoints.

use frankenlibc_abi::wchar_abi::{
    btowc, fgetwc, fgetws, fputwc, fputws, mbrtowc, mbsrtowcs, mkstemp, realpath, ungetwc,
    wcrtomb, wcscoll, wcsftime, wcsnlen, wcsrtombs, wcswidth, wcsxfrm, wcstod, wcstof, wcstol,
    wcstold, wcstoll, wcstoul, wcstoull, wctob,
};

fn errno_value() -> i32 {
    // SAFETY: frankenlibc ABI exposes thread-local errno pointer for current thread.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

fn set_errno(value: i32) {
    // SAFETY: frankenlibc ABI exposes thread-local errno pointer for current thread.
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = value;
    }
}

#[test]
fn mkstemp_creates_unique_file_and_rewrites_template() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let mut template = format!("/tmp/frankenlibc-wchar-mkstemp-{stamp}-XXXXXX\0").into_bytes();

    // SAFETY: writable NUL-terminated template.
    let fd = unsafe { mkstemp(template.as_mut_ptr().cast()) };
    assert!(fd >= 0);

    // SAFETY: template remains valid C string after mkstemp in-place rewrite.
    let path = unsafe { std::ffi::CStr::from_ptr(template.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();
    assert!(!path.ends_with("XXXXXX"));

    // SAFETY: close descriptor returned by mkstemp.
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
    // SAFETY: input is valid C string and output buffer is writable.
    let result = unsafe { realpath(input.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(result, out.as_mut_ptr());
    assert!(!result.is_null());

    // SAFETY: result points to NUL-terminated bytes in `out`.
    let resolved = unsafe { std::ffi::CStr::from_ptr(result) }
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

    // SAFETY: `value` is a valid, in-bounds wide string buffer.
    assert_eq!(unsafe { wcsnlen(value.as_ptr(), 8) }, 2);
    // SAFETY: same as above; bound limits reads to one element.
    assert_eq!(unsafe { wcsnlen(value.as_ptr(), 1) }, 1);
}

#[test]
fn wcswidth_reports_width_and_nonprintable() {
    let printable: [libc::wchar_t; 3] = [b'A' as libc::wchar_t, 0x754c_i32, 0];
    let non_printable: [libc::wchar_t; 2] = [0x07, 0];

    // SAFETY: both pointers reference valid NUL-terminated wide strings.
    assert_eq!(unsafe { wcswidth(printable.as_ptr(), 8) }, 3);
    // SAFETY: bound constrains scan to first character.
    assert_eq!(unsafe { wcswidth(printable.as_ptr(), 1) }, 1);
    // SAFETY: same buffer guarantees.
    assert_eq!(unsafe { wcswidth(non_printable.as_ptr(), 8) }, -1);
}

#[test]
fn wctob_and_btowc_roundtrip_ascii_only() {
    // SAFETY: pure value conversion, no pointer dereference.
    assert_eq!(unsafe { wctob(b'Z' as u32) }, b'Z' as i32);
    // SAFETY: pure value conversion.
    assert_eq!(unsafe { wctob(0x80) }, libc::EOF);

    // SAFETY: pure value conversion.
    assert_eq!(unsafe { btowc(libc::EOF) }, u32::MAX);
    // SAFETY: pure value conversion.
    assert_eq!(unsafe { btowc(b'Z' as i32) }, b'Z' as u32);
    // SAFETY: pure value conversion.
    assert_eq!(unsafe { btowc(0x80) }, u32::MAX);
}

#[test]
fn wcrtomb_encodes_ascii_and_reports_invalid() {
    let mut out = [0_i8; 4];

    // SAFETY: out buffer is writable and large enough for UTF-8 sequence.
    let n = unsafe { wcrtomb(out.as_mut_ptr(), b'A' as libc::wchar_t, std::ptr::null_mut()) };
    assert_eq!(n, 1);
    assert_eq!(out[0] as u8, b'A');

    set_errno(0);
    // SAFETY: invalid code point should fail with EILSEQ.
    let invalid = unsafe { wcrtomb(out.as_mut_ptr(), 0x110000_i32, std::ptr::null_mut()) };
    assert_eq!(invalid, usize::MAX);
    assert_eq!(errno_value(), libc::EILSEQ);
}

#[test]
fn mbrtowc_handles_success_incomplete_and_invalid() {
    let mut wc: libc::wchar_t = 0;
    let ascii = [b'Z' as i8];

    // SAFETY: input buffer is valid and pwc is writable.
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
    // SAFETY: incomplete UTF-8 sequence with n=1 must report -2.
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
    // SAFETY: invalid leading byte must report -1 and set EILSEQ.
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
    let src = [0xC3_u8 as i8, 0xA9_u8 as i8, b'A' as i8, 0];
    let mut src_ptr = src.as_ptr();
    let mut dst = [0_i32; 8];

    // SAFETY: pointers are valid and destination has enough room.
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
fn wcsrtombs_converts_and_updates_source_pointer() {
    let src = [b'A' as i32, 0x754c_i32, 0];
    let mut src_ptr = src.as_ptr();
    let mut dst = [0_i8; 16];

    // SAFETY: pointers are valid and destination has enough room.
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

    // SAFETY: valid NUL-terminated input and writable endptr.
    let value = unsafe { wcstol(input.as_ptr(), &mut end as *mut *mut libc::wchar_t, 10) };
    assert_eq!(value, -12);
    // SAFETY: both pointers originate from the same input array.
    assert_eq!(unsafe { end.offset_from(input.as_ptr() as *mut libc::wchar_t) }, 4);

    set_errno(0);
    end = std::ptr::null_mut();
    // SAFETY: invalid base should fail deterministically with EINVAL.
    let invalid_base = unsafe { wcstol(input.as_ptr(), &mut end as *mut *mut libc::wchar_t, 1) };
    assert_eq!(invalid_base, 0);
    assert_eq!(errno_value(), libc::EINVAL);
    // SAFETY: both pointers originate from the same input array.
    assert_eq!(unsafe { end.offset_from(input.as_ptr() as *mut libc::wchar_t) }, 0);
}

#[test]
fn wcstoul_reports_overflow_and_aliases_follow() {
    let digits = "18446744073709551616";
    let mut wide: Vec<libc::wchar_t> = digits.bytes().map(|b| b as libc::wchar_t).collect();
    wide.push(0);

    let mut end: *mut libc::wchar_t = std::ptr::null_mut();
    set_errno(0);
    // SAFETY: valid NUL-terminated input and writable endptr.
    let value = unsafe { wcstoul(wide.as_ptr(), &mut end as *mut *mut libc::wchar_t, 10) };
    assert_eq!(value as u64, u64::MAX);
    assert_eq!(errno_value(), libc::ERANGE);
    // SAFETY: both pointers originate from the same input buffer.
    assert_eq!(unsafe { end.offset_from(wide.as_ptr() as *mut libc::wchar_t) }, digits.len() as isize);

    end = std::ptr::null_mut();
    set_errno(0);
    // SAFETY: alias should share parsing + errno behavior.
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

    // SAFETY: valid NUL-terminated input and writable endptr.
    let d = unsafe { wcstod(input.as_ptr(), &mut end as *mut *mut libc::wchar_t) };
    assert!((d - 12.5).abs() < 1e-10);
    // SAFETY: both pointers originate from the same input array.
    assert_eq!(unsafe { end.offset_from(input.as_ptr() as *mut libc::wchar_t) }, 4);

    end = std::ptr::null_mut();
    // SAFETY: alias should share conversion and pointer progression.
    let f = unsafe { wcstof(input.as_ptr(), &mut end as *mut *mut libc::wchar_t) };
    assert!((f - 12.5_f32).abs() < 1e-5);
    // SAFETY: both pointers originate from the same input array.
    assert_eq!(unsafe { end.offset_from(input.as_ptr() as *mut libc::wchar_t) }, 4);

    end = std::ptr::null_mut();
    // SAFETY: long double is currently modeled as f64 in this ABI.
    let ld = unsafe { wcstold(input.as_ptr(), &mut end as *mut *mut libc::wchar_t) };
    assert!((ld - 12.5).abs() < 1e-10);

    let signed: [libc::wchar_t; 4] = [
        b'-' as libc::wchar_t,
        b'7' as libc::wchar_t,
        b'9' as libc::wchar_t,
        0,
    ];
    end = std::ptr::null_mut();
    // SAFETY: alias should match signed conversion semantics.
    let ll = unsafe { wcstoll(signed.as_ptr(), &mut end as *mut *mut libc::wchar_t, 10) };
    assert_eq!(ll, -79);
}

#[test]
fn wcscoll_and_wcsxfrm_follow_c_locale_contract() {
    let a: [libc::wchar_t; 3] = [b'a' as libc::wchar_t, b'b' as libc::wchar_t, 0];
    let b: [libc::wchar_t; 3] = [b'a' as libc::wchar_t, b'c' as libc::wchar_t, 0];

    // SAFETY: valid NUL-terminated wide strings.
    assert!(unsafe { wcscoll(a.as_ptr(), b.as_ptr()) } < 0);
    // SAFETY: valid NUL-terminated wide strings.
    assert!(unsafe { wcscoll(b.as_ptr(), a.as_ptr()) } > 0);
    // SAFETY: valid NUL-terminated wide strings.
    assert_eq!(unsafe { wcscoll(a.as_ptr(), a.as_ptr()) }, 0);

    let src: [libc::wchar_t; 4] = [
        b'a' as libc::wchar_t,
        b'b' as libc::wchar_t,
        b'c' as libc::wchar_t,
        0,
    ];
    let mut dst = [0_i32; 2];
    // SAFETY: destination has room for n elements, source is NUL-terminated.
    let needed = unsafe { wcsxfrm(dst.as_mut_ptr(), src.as_ptr(), dst.len()) };
    assert_eq!(needed, 3);
    assert_eq!(dst[0] as u8, b'a');
    assert_eq!(dst[1], 0);
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

    // 2026-01-02 03:04:05 UTC-like broken-down value.
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

    // SAFETY: output and format buffers are valid; tm points to initialized struct.
    let written = unsafe {
        wcsftime(
            out.as_mut_ptr(),
            out.len(),
            fmt.as_ptr(),
            &tm as *const libc::tm as *const std::ffi::c_void,
        )
    };
    assert_eq!(written, 10);
    let rendered: Vec<u32> = out[..written].iter().map(|&ch| ch as u32).collect();
    assert_eq!(rendered, "2026-01-02".bytes().map(u32::from).collect::<Vec<_>>());
}

#[test]
fn wide_stream_char_roundtrip_and_pushback() {
    // SAFETY: creates an isolated temporary stream owned by this test.
    let stream = unsafe { frankenlibc_abi::stdio_abi::tmpfile() };
    assert!(!stream.is_null());

    // SAFETY: valid stream handle from tmpfile.
    assert_eq!(unsafe { fputwc('é' as u32, stream) }, 'é' as u32);
    // SAFETY: valid stream handle from tmpfile.
    assert_eq!(unsafe { fputwc('A' as u32, stream) }, 'A' as u32);
    // SAFETY: reposition to stream start for reading.
    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fseek(stream, 0, libc::SEEK_SET) }, 0);

    // SAFETY: valid stream handle.
    assert_eq!(unsafe { fgetwc(stream) }, 'é' as u32);
    // SAFETY: valid stream handle.
    assert_eq!(unsafe { fgetwc(stream) }, 'A' as u32);
    // SAFETY: EOF read should map to WEOF.
    assert_eq!(unsafe { fgetwc(stream) }, u32::MAX);

    // SAFETY: reset and exercise ungetwc ordering.
    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fseek(stream, 0, libc::SEEK_SET) }, 0);
    // SAFETY: valid stream handle.
    assert_eq!(unsafe { ungetwc('Z' as u32, stream) }, 'Z' as u32);
    // SAFETY: pushback character is returned first.
    assert_eq!(unsafe { fgetwc(stream) }, 'Z' as u32);
    // SAFETY: then underlying file content resumes.
    assert_eq!(unsafe { fgetwc(stream) }, 'é' as u32);

    // SAFETY: close owned stream.
    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(stream) }, 0);
}

#[test]
fn wide_stream_string_io_handles_newline_splitting() {
    // SAFETY: creates an isolated temporary stream owned by this test.
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

    // SAFETY: valid stream and NUL-terminated source.
    assert_eq!(unsafe { fputws(src.as_ptr(), stream) }, 0);
    // SAFETY: rewind to beginning.
    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut buf = [0_i32; 16];
    // SAFETY: valid destination and stream.
    let first = unsafe { fgetws(buf.as_mut_ptr(), buf.len() as i32, stream) };
    assert!(!first.is_null());
    let first_len = buf.iter().position(|&ch| ch == 0).unwrap_or(buf.len());
    let first_text: Vec<u8> = buf[..first_len].iter().map(|&ch| ch as u8).collect();
    assert_eq!(first_text, b"hi\n");

    buf.fill(0);
    // SAFETY: valid destination and stream.
    let second = unsafe { fgetws(buf.as_mut_ptr(), buf.len() as i32, stream) };
    assert!(!second.is_null());
    let second_len = buf.iter().position(|&ch| ch == 0).unwrap_or(buf.len());
    let second_text: Vec<u8> = buf[..second_len].iter().map(|&ch| ch as u8).collect();
    assert_eq!(second_text, b"there");

    // SAFETY: now EOF should yield null.
    assert!(unsafe { fgetws(buf.as_mut_ptr(), buf.len() as i32, stream) }.is_null());

    // SAFETY: close owned stream.
    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(stream) }, 0);
}
