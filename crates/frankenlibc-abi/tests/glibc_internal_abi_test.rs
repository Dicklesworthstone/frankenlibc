#![cfg(target_os = "linux")]

//! Integration tests for glibc_internal_abi entrypoints.

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::glibc_internal_abi::{
    __asprintf,
    __call_tls_dtors,
    __copy_grp,
    __file_change_detection_for_path,
    __file_change_detection_for_stat,
    __file_is_unchanged,
    __fseeko64,
    __ftello64,
    __gconv,
    __gconv_close,
    __gconv_create_spec,
    __gconv_destroy_spec,
    __gconv_get_alias_db,
    __gconv_get_cache,
    __gconv_get_modules_db,
    __gconv_open,
    __gconv_transliterate,
    __idna_from_dns_encoding,
    __idna_to_dns_encoding,
    __inet_aton_exact,
    __inet_pton_length,
    __inet6_scopeid_pton,
    __merge_grp,
    __mktemp,
    __ns_name_compress,
    __ns_name_ntop,
    __ns_name_pack,
    __ns_name_pton,
    __ns_name_skip,
    __ns_name_uncompress,
    __ns_name_uncompressed_p,
    __ns_name_unpack,
    __ns_samename,
    __nss_configure_lookup,
    __nss_database_lookup,
    __nss_group_lookup,
    __nss_hostname_digits_dots,
    __nss_hosts_lookup,
    __nss_next,
    __nss_passwd_lookup,
    __overflow,
    __pread64,
    __pread64_nocancel,
    __printf_fp,
    __read,
    __read_nocancel,
    // Session 13 additions:
    __res_mkquery,
    __res_send,
    __res_state,
    __resolv_context_freeres,
    __resolv_context_get,
    __resolv_context_get_override,
    __resolv_context_get_preinit,
    __resolv_context_put,
    __shm_get_name,
    __strlcat_chk,
    __strlcpy_chk,
    __strtof128_internal,
    __twalk_r,
    __uflow,
    __underflow,
    __wcpcpy_chk,
    __wcslcat_chk,
    __wcslcpy_chk,
    __wcstof128_internal,
    __woverflow,
    __wuflow,
    __wunderflow,
    _dl_find_object,
    _obstack_allocated_p,
    _obstack_begin,
    _obstack_free,
    _obstack_memory_used,
    _obstack_newchunk,
    _pthread_cleanup_pop,
    _pthread_cleanup_pop_restore,
    _pthread_cleanup_push,
    _pthread_cleanup_push_defer,
    getpw,
    inet6_opt_append,
    inet6_opt_find,
    inet6_opt_finish,
    inet6_opt_get_val,
    inet6_opt_init,
    inet6_opt_next,
    inet6_opt_set_val,
    inet6_rth_add,
    inet6_rth_getaddr,
    inet6_rth_init,
    inet6_rth_reverse,
    inet6_rth_segments,
    inet6_rth_space,
    iruserok,
    iruserok_af,
    ns_name_compress,
    ns_name_ntop,
    ns_name_pack,
    ns_name_pton,
    ns_name_skip,
    ns_name_uncompress,
    ns_name_unpack,
    parse_printf_format,
    printf_size,
    printf_size_info,
    putgrent,
    putpwent,
    rcmd,
    rcmd_af,
    register_printf_function,
    register_printf_modifier,
    register_printf_specifier,
    register_printf_type,
    res_dnok,
    res_hnok,
    res_mailok,
    res_mkquery,
    res_nmkquery,
    res_nquery,
    res_nquerydomain,
    res_nsearch,
    res_nsend,
    res_ownok,
    res_querydomain,
    res_send,
    rexec,
    rexec_af,
    ruserok,
    ruserok_af,
    ruserpass,
    sgetspent_r,
    wcswcs,
    xprt_register,
    xprt_unregister,
};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;

// ===========================================================================
// DNS name validators
// ===========================================================================

#[test]
fn res_hnok_accepts_valid_hostnames() {
    let valid = CString::new("example.com").unwrap();
    assert_eq!(unsafe { res_hnok(valid.as_ptr()) }, 1);

    let with_hyphen = CString::new("my-host.example.com").unwrap();
    assert_eq!(unsafe { res_hnok(with_hyphen.as_ptr()) }, 1);

    let single = CString::new("localhost").unwrap();
    assert_eq!(unsafe { res_hnok(single.as_ptr()) }, 1);
}

#[test]
fn res_hnok_rejects_invalid_hostnames() {
    let underscore = CString::new("bad_host.com").unwrap();
    assert_eq!(unsafe { res_hnok(underscore.as_ptr()) }, 0);

    let space = CString::new("bad host").unwrap();
    assert_eq!(unsafe { res_hnok(space.as_ptr()) }, 0);

    assert_eq!(unsafe { res_hnok(ptr::null()) }, 0);
}

#[test]
fn res_dnok_accepts_underscores() {
    let with_underscore = CString::new("_sip._tcp.example.com").unwrap();
    assert_eq!(unsafe { res_dnok(with_underscore.as_ptr()) }, 1);

    let normal = CString::new("example.com").unwrap();
    assert_eq!(unsafe { res_dnok(normal.as_ptr()) }, 1);
}

#[test]
fn res_mailok_accepts_mailbox_label() {
    // res_mailok allows more chars in first label (mailbox part) but NOT '@'
    // In DNS mail notation, user.example.com represents user@example.com
    let maildom = CString::new("user.example.com").unwrap();
    assert_eq!(unsafe { res_mailok(maildom.as_ptr()) }, 1);

    // First label can contain chars that hostnames can't (like +, etc.)
    let plus = CString::new("user+tag.example.com").unwrap();
    assert_eq!(unsafe { res_mailok(plus.as_ptr()) }, 1);
}

#[test]
fn res_ownok_delegates_to_dnok() {
    let valid = CString::new("_srv.example.com").unwrap();
    assert_eq!(unsafe { res_ownok(valid.as_ptr()) }, 1);

    let invalid = CString::new("bad name").unwrap();
    assert_eq!(unsafe { res_ownok(invalid.as_ptr()) }, 0);
}

// ===========================================================================
// gconv shims over native iconv
// ===========================================================================

#[test]
fn gconv_open_and_close_roundtrip() {
    let to = CString::new("UTF-16LE").unwrap();
    let from = CString::new("UTF-8").unwrap();
    let mut handle = ptr::null_mut();

    let rc = unsafe { __gconv_open(to.as_ptr(), from.as_ptr(), &mut handle, 0) };
    assert_eq!(rc, 0);
    assert!(!handle.is_null());
    assert_eq!(unsafe { __gconv_close(handle) }, 0);
}

#[test]
fn gconv_open_unsupported_codec_returns_noconv() {
    let to = CString::new("EBCDIC").unwrap();
    let from = CString::new("UTF-8").unwrap();
    let mut handle = ptr::null_mut();

    let rc = unsafe { __gconv_open(to.as_ptr(), from.as_ptr(), &mut handle, 0) };
    assert_eq!(rc, -1);
    assert!(handle.is_null());
}

#[test]
fn gconv_close_rejects_null_handle() {
    assert_eq!(unsafe { __gconv_close(ptr::null_mut()) }, -1);
}

// ---------------------------------------------------------------------------
// __gconv_create_spec / __gconv_destroy_spec — native safe-default tests
// ---------------------------------------------------------------------------

#[test]
fn gconv_create_spec_null_returns_noconv() {
    let rc = unsafe { __gconv_create_spec(ptr::null_mut()) };
    assert_eq!(rc, -1); // GCONV_NOCONV
}

#[test]
fn gconv_create_spec_valid_buffer_returns_ok_and_zeroes() {
    let mut buf = [0xFFu8; 64];
    let rc = unsafe { __gconv_create_spec(buf.as_mut_ptr().cast()) };
    assert_eq!(rc, 0); // GCONV_OK
    assert!(buf.iter().all(|&b| b == 0), "spec buffer should be zeroed");
}

#[test]
fn gconv_destroy_spec_null_is_safe_noop() {
    // Must not panic or crash
    unsafe { __gconv_destroy_spec(ptr::null_mut()) };
}

#[test]
fn gconv_destroy_spec_valid_buffer_is_safe_noop() {
    let mut buf = [0u8; 64];
    unsafe { __gconv_destroy_spec(buf.as_mut_ptr().cast()) };
}

#[test]
fn gconv_create_destroy_roundtrip() {
    let mut buf = [0xFFu8; 64];
    let rc = unsafe { __gconv_create_spec(buf.as_mut_ptr().cast()) };
    assert_eq!(rc, 0);
    unsafe { __gconv_destroy_spec(buf.as_mut_ptr().cast()) };
}

// ---------------------------------------------------------------------------
// __gconv_get_* database accessors — native safe-default tests
// ---------------------------------------------------------------------------

#[test]
fn gconv_get_alias_db_returns_null() {
    assert!(unsafe { __gconv_get_alias_db() }.is_null());
}

#[test]
fn gconv_get_cache_returns_null() {
    assert!(unsafe { __gconv_get_cache() }.is_null());
}

#[test]
fn gconv_get_modules_db_returns_null() {
    assert!(unsafe { __gconv_get_modules_db() }.is_null());
}

// ---------------------------------------------------------------------------
// __gconv — conversion step — native safe-default tests
// ---------------------------------------------------------------------------

#[test]
fn gconv_step_returns_noconv_and_zeroes_written() {
    let mut written: usize = 42;
    let rc = unsafe {
        __gconv(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut written,
        )
    };
    assert_eq!(rc, -1); // GCONV_NOCONV
    assert_eq!(written, 0, "written count should be zeroed");
}

#[test]
fn gconv_step_null_written_ptr_does_not_crash() {
    let rc = unsafe {
        __gconv(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(rc, -1); // GCONV_NOCONV
}

// ---------------------------------------------------------------------------
// __gconv_transliterate — native safe-default tests
// ---------------------------------------------------------------------------

#[test]
fn gconv_transliterate_returns_noconv() {
    let rc = unsafe {
        __gconv_transliterate(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
        )
    };
    assert_eq!(rc, -1); // GCONV_NOCONV
}

// ===========================================================================
// parse_printf_format
// ===========================================================================

const PA_INT: i32 = 1;
const PA_CHAR: i32 = 2;
const PA_STRING: i32 = 4;
const PA_POINTER: i32 = 6;
const PA_DOUBLE: i32 = 8;
const PA_FLAG_LONG: i32 = 0x100;
const PA_FLAG_LONG_LONG: i32 = 0x200;

#[test]
fn parse_printf_format_simple_types() {
    let fmt = CString::new("%d %s %f %p").unwrap();
    let mut types = [0i32; 8];
    let count = unsafe { parse_printf_format(fmt.as_ptr(), 8, types.as_mut_ptr()) };
    assert_eq!(count, 4);
    assert_eq!(types[0], PA_INT);
    assert_eq!(types[1], PA_STRING);
    assert_eq!(types[2], PA_DOUBLE);
    assert_eq!(types[3], PA_POINTER);
}

#[test]
fn parse_printf_format_length_modifiers() {
    let fmt = CString::new("%ld %lld %hd %c").unwrap();
    let mut types = [0i32; 8];
    let count = unsafe { parse_printf_format(fmt.as_ptr(), 8, types.as_mut_ptr()) };
    assert_eq!(count, 4);
    assert_eq!(types[0], PA_INT | PA_FLAG_LONG);
    assert_eq!(types[1], PA_INT | PA_FLAG_LONG_LONG);
    assert_eq!(types[2], PA_INT | 0x400); // PA_FLAG_SHORT
    assert_eq!(types[3], PA_CHAR);
}

#[test]
fn parse_printf_format_star_width_and_precision() {
    let fmt = CString::new("%*.*f").unwrap();
    let mut types = [0i32; 8];
    let count = unsafe { parse_printf_format(fmt.as_ptr(), 8, types.as_mut_ptr()) };
    // star width → int, star precision → int, then double
    assert_eq!(count, 3);
    assert_eq!(types[0], PA_INT);
    assert_eq!(types[1], PA_INT);
    assert_eq!(types[2], PA_DOUBLE);
}

#[test]
fn parse_printf_format_percent_literal_not_counted() {
    let fmt = CString::new("100%% done %d").unwrap();
    let mut types = [0i32; 8];
    let count = unsafe { parse_printf_format(fmt.as_ptr(), 8, types.as_mut_ptr()) };
    assert_eq!(count, 1);
    assert_eq!(types[0], PA_INT);
}

#[test]
fn parse_printf_format_null_argtypes_just_counts() {
    let fmt = CString::new("%d %s %f").unwrap();
    let count = unsafe { parse_printf_format(fmt.as_ptr(), 0, ptr::null_mut()) };
    assert_eq!(count, 3);
}

#[test]
fn parse_printf_format_null_fmt_returns_zero() {
    let count = unsafe { parse_printf_format(ptr::null(), 0, ptr::null_mut()) };
    assert_eq!(count, 0);
}

// ===========================================================================
// Security deny stubs: rcmd/rexec/ruserok/iruserok/ruserpass
// ===========================================================================

#[test]
fn iruserok_always_denies() {
    let user = CString::new("root").unwrap();
    let ruser = CString::new("attacker").unwrap();
    let result = unsafe { iruserok(0x7f000001, 0, ruser.as_ptr(), user.as_ptr()) };
    assert_eq!(result, -1, "iruserok should deny all .rhosts auth");
}

#[test]
fn iruserok_af_always_denies() {
    let user = CString::new("root").unwrap();
    let ruser = CString::new("attacker").unwrap();
    let addr: u32 = 0x7f000001;
    let result = unsafe {
        iruserok_af(
            &addr as *const u32 as *const std::ffi::c_void,
            0,
            ruser.as_ptr(),
            user.as_ptr(),
            libc::AF_INET,
        )
    };
    assert_eq!(result, -1);
}

#[test]
fn ruserok_always_denies() {
    let host = CString::new("attacker.example.com").unwrap();
    let user = CString::new("root").unwrap();
    let ruser = CString::new("attacker").unwrap();
    let result = unsafe { ruserok(host.as_ptr(), 0, ruser.as_ptr(), user.as_ptr()) };
    assert_eq!(result, -1);
}

#[test]
fn ruserok_af_always_denies() {
    let host = CString::new("attacker.example.com").unwrap();
    let user = CString::new("root").unwrap();
    let ruser = CString::new("attacker").unwrap();
    let result = unsafe {
        ruserok_af(
            host.as_ptr(),
            0,
            ruser.as_ptr(),
            user.as_ptr(),
            libc::AF_INET,
        )
    };
    assert_eq!(result, -1);
}

#[test]
fn rcmd_returns_enosys() {
    let host = CString::new("target.example.com").unwrap();
    let mut host_ptr = host.as_ptr() as *mut libc::c_char;
    let user = CString::new("user").unwrap();
    let cmd = CString::new("id").unwrap();
    let result = unsafe {
        rcmd(
            &mut host_ptr,
            514,
            user.as_ptr(),
            user.as_ptr(),
            cmd.as_ptr(),
            ptr::null_mut(),
        )
    };
    assert_eq!(result, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::ENOSYS);
}

#[test]
fn rcmd_af_returns_enosys() {
    let host = CString::new("target.example.com").unwrap();
    let mut host_ptr = host.as_ptr() as *mut libc::c_char;
    let user = CString::new("user").unwrap();
    let cmd = CString::new("id").unwrap();
    let result = unsafe {
        rcmd_af(
            &mut host_ptr,
            514,
            user.as_ptr(),
            user.as_ptr(),
            cmd.as_ptr(),
            ptr::null_mut(),
            libc::AF_INET,
        )
    };
    assert_eq!(result, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::ENOSYS);
}

#[test]
fn rexec_returns_enosys() {
    let host = CString::new("target.example.com").unwrap();
    let mut host_ptr = host.as_ptr() as *mut libc::c_char;
    let user = CString::new("user").unwrap();
    let pass = CString::new("pass").unwrap();
    let cmd = CString::new("id").unwrap();
    let result = unsafe {
        rexec(
            &mut host_ptr,
            512,
            user.as_ptr(),
            pass.as_ptr(),
            cmd.as_ptr(),
            ptr::null_mut(),
        )
    };
    assert_eq!(result, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::ENOSYS);
}

#[test]
fn rexec_af_returns_enosys() {
    let host = CString::new("target.example.com").unwrap();
    let mut host_ptr = host.as_ptr() as *mut libc::c_char;
    let user = CString::new("user").unwrap();
    let pass = CString::new("pass").unwrap();
    let cmd = CString::new("id").unwrap();
    let result = unsafe {
        rexec_af(
            &mut host_ptr,
            512,
            user.as_ptr(),
            pass.as_ptr(),
            cmd.as_ptr(),
            ptr::null_mut(),
            libc::AF_INET,
        )
    };
    assert_eq!(result, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::ENOSYS);
}

#[test]
fn ruserpass_returns_error_with_null_credentials() {
    let host = CString::new("example.com").unwrap();
    let mut name_ptr: *const libc::c_char = ptr::null();
    let mut pass_ptr: *const libc::c_char = ptr::null();
    let result = unsafe { ruserpass(host.as_ptr(), &mut name_ptr, &mut pass_ptr) };
    assert_eq!(result, -1);
    assert!(name_ptr.is_null(), "ruserpass should not set name");
    assert!(pass_ptr.is_null(), "ruserpass should not set pass");
}

// ===========================================================================
// ns_name_* DNS wire format (7 symbols)
// ===========================================================================

// Helper: build wire-format labels from dotted name (for test setup).
fn make_wire_name(dotted: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let parts: Vec<&str> = if dotted.is_empty() {
        vec![]
    } else {
        dotted.split('.').collect()
    };
    for label in &parts {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root terminator
    out
}

unsafe fn malloc_unterminated(bytes: &[u8]) -> *mut c_char {
    let raw = unsafe { frankenlibc_abi::malloc_abi::malloc(bytes.len()) }.cast::<u8>();
    assert!(!raw.is_null());
    let usable = unsafe { frankenlibc_abi::malloc_abi::malloc_usable_size(raw.cast()) };
    unsafe { std::ptr::write_bytes(raw, 0x7f, usable.max(bytes.len())) };
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), raw, bytes.len()) };
    raw.cast()
}

unsafe fn malloc_unterminated_wide(wchars: &[libc::wchar_t]) -> *mut libc::wchar_t {
    let bytes = std::mem::size_of_val(wchars);
    let raw = unsafe { frankenlibc_abi::malloc_abi::malloc(bytes) }.cast::<u8>();
    assert!(!raw.is_null());
    let usable = unsafe { frankenlibc_abi::malloc_abi::malloc_usable_size(raw.cast()) };
    unsafe { std::ptr::write_bytes(raw, 0x7f, usable.max(bytes)) };
    unsafe { std::ptr::copy_nonoverlapping(wchars.as_ptr(), raw.cast(), wchars.len()) };
    raw.cast()
}

unsafe fn malloc_tracked_zeroed_bytes(len: usize) -> *mut c_void {
    assert!(len > 0);
    let raw = unsafe { frankenlibc_abi::malloc_abi::malloc(len) };
    assert!(!raw.is_null());
    unsafe { std::ptr::write_bytes(raw.cast::<u8>(), 0, len) };
    raw
}

fn clear_errno() {
    unsafe { *__errno_location() = 0 };
}

fn errno_value() -> c_int {
    unsafe { *__errno_location() }
}

fn pipe_with_payload(payload: &[u8]) -> [c_int; 2] {
    let mut fds = [-1, -1];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    assert_eq!(
        unsafe { libc::write(fds[1], payload.as_ptr().cast(), payload.len()) },
        payload.len() as isize,
    );
    fds
}

fn memfd_with_payload(payload: &[u8]) -> c_int {
    let name = CString::new("frankenlibc-internal-pread").unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) as c_int };
    assert!(fd >= 0, "memfd_create failed with errno {}", errno_value());
    assert_eq!(
        unsafe { libc::write(fd, payload.as_ptr().cast(), payload.len()) },
        payload.len() as isize,
    );
    fd
}

#[test]
fn strl_chk_bounds_tracked_unterminated_source() {
    unsafe {
        let src = malloc_unterminated(b"ABC");
        let mut copied = [0 as c_char; 2];
        let copied_len = __strlcpy_chk(copied.as_mut_ptr(), src, copied.len(), copied.len());
        assert_eq!(copied_len, 3);
        assert_eq!(copied[0] as u8, b'A');
        assert_eq!(copied[1], 0);

        let mut appended = [0 as c_char; 3];
        appended[0] = b'X' as c_char;
        appended[1] = 0;
        let appended_len =
            __strlcat_chk(appended.as_mut_ptr(), src, appended.len(), appended.len());
        assert_eq!(appended_len, 4);
        assert_eq!(appended[0] as u8, b'X');
        assert_eq!(appended[1] as u8, b'A');
        assert_eq!(appended[2], 0);

        frankenlibc_abi::malloc_abi::free(src.cast());
    }
}

#[test]
fn internal_read_rejects_tracked_short_output_buffer() {
    let fds = pipe_with_payload(b"read");
    unsafe {
        let raw = malloc_tracked_zeroed_bytes(1);
        clear_errno();
        let n = __read(fds[0], raw, 4);
        assert_eq!(n, -1);
        assert_eq!(errno_value(), libc::EFAULT);
        assert_eq!(raw.cast::<u8>().read(), 0);
        frankenlibc_abi::malloc_abi::free(raw);
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn internal_read_nocancel_rejects_tracked_short_output_buffer() {
    let fds = pipe_with_payload(b"read");
    unsafe {
        let raw = malloc_tracked_zeroed_bytes(1);
        clear_errno();
        let n = __read_nocancel(fds[0], raw, 4);
        assert_eq!(n, -1);
        assert_eq!(errno_value(), libc::EFAULT);
        assert_eq!(raw.cast::<u8>().read(), 0);
        frankenlibc_abi::malloc_abi::free(raw);
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn internal_pread64_rejects_tracked_short_output_buffer() {
    let fd = memfd_with_payload(b"pread");
    unsafe {
        let raw = malloc_tracked_zeroed_bytes(1);
        clear_errno();
        let n = __pread64(fd, raw, 5, 0);
        assert_eq!(n, -1);
        assert_eq!(errno_value(), libc::EFAULT);
        assert_eq!(raw.cast::<u8>().read(), 0);
        frankenlibc_abi::malloc_abi::free(raw);
        libc::close(fd);
    }
}

#[test]
fn internal_pread64_nocancel_rejects_tracked_short_output_buffer() {
    let fd = memfd_with_payload(b"pread");
    unsafe {
        let raw = malloc_tracked_zeroed_bytes(1);
        clear_errno();
        let n = __pread64_nocancel(fd, raw, 5, 0);
        assert_eq!(n, -1);
        assert_eq!(errno_value(), libc::EFAULT);
        assert_eq!(raw.cast::<u8>().read(), 0);
        frankenlibc_abi::malloc_abi::free(raw);
        libc::close(fd);
    }
}

#[test]
fn wcsl_chk_bounds_tracked_unterminated_source() {
    unsafe {
        let src = malloc_unterminated_wide(&[
            b'A' as libc::wchar_t,
            b'B' as libc::wchar_t,
            b'C' as libc::wchar_t,
        ]);
        let mut copied = [0 as libc::wchar_t; 2];
        let copied_len = __wcslcpy_chk(copied.as_mut_ptr(), src, copied.len(), copied.len());
        assert_eq!(copied_len, 3);
        assert_eq!(copied[0], b'A' as libc::wchar_t);
        assert_eq!(copied[1], 0);

        let mut appended = [0 as libc::wchar_t; 3];
        appended[0] = b'X' as libc::wchar_t;
        appended[1] = 0;
        let appended_len =
            __wcslcat_chk(appended.as_mut_ptr(), src, appended.len(), appended.len());
        assert_eq!(appended_len, 4);
        assert_eq!(appended[0], b'X' as libc::wchar_t);
        assert_eq!(appended[1], b'A' as libc::wchar_t);
        assert_eq!(appended[2], 0);

        frankenlibc_abi::malloc_abi::free(src.cast());
    }
}

#[test]
fn wcpcpy_chk_copies_and_returns_end_pointer() {
    let src = [
        b'A' as libc::wchar_t,
        b'B' as libc::wchar_t,
        0 as libc::wchar_t,
    ];
    let mut dst = [0 as libc::wchar_t; 3];
    let end = unsafe { __wcpcpy_chk(dst.as_mut_ptr(), src.as_ptr(), dst.len()) };
    assert_eq!(dst, src);
    assert_eq!(end, unsafe { dst.as_mut_ptr().add(2) });
}

#[test]
fn wcswcs_finds_substring() {
    let hay = [
        b'A' as libc::wchar_t,
        b'B' as libc::wchar_t,
        b'C' as libc::wchar_t,
        0 as libc::wchar_t,
    ];
    let needle = [
        b'B' as libc::wchar_t,
        b'C' as libc::wchar_t,
        0 as libc::wchar_t,
    ];
    let found = unsafe { wcswcs(hay.as_ptr(), needle.as_ptr()) };
    assert_eq!(found, unsafe { hay.as_ptr().add(1) as *mut libc::wchar_t });
}

#[test]
fn wcswcs_bounds_tracked_unterminated_inputs() {
    unsafe {
        let hay = malloc_unterminated_wide(&[
            b'A' as libc::wchar_t,
            b'B' as libc::wchar_t,
            b'C' as libc::wchar_t,
        ]);
        let missing = [b'Z' as libc::wchar_t, 0 as libc::wchar_t];
        assert!(wcswcs(hay, missing.as_ptr()).is_null());

        let terminated_hay = [
            b'A' as libc::wchar_t,
            b'B' as libc::wchar_t,
            b'C' as libc::wchar_t,
            0 as libc::wchar_t,
        ];
        let unterminated_needle = malloc_unterminated_wide(&[b'B' as libc::wchar_t]);
        assert!(wcswcs(terminated_hay.as_ptr(), unterminated_needle).is_null());

        frankenlibc_abi::malloc_abi::free(hay.cast());
        frankenlibc_abi::malloc_abi::free(unterminated_needle.cast());
    }
}

#[test]
fn ns_name_pton_encodes_domain_to_wire() {
    let name = CString::new("example.com").unwrap();
    let mut buf = [0u8; 64];
    let ret = unsafe { ns_name_pton(name.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len()) };
    assert!(ret > 0, "ns_name_pton returned {ret}");
    // Expected wire: \x07example\x03com\x00
    assert_eq!(buf[0], 7); // "example" length
    assert_eq!(&buf[1..8], b"example");
    assert_eq!(buf[8], 3); // "com" length
    assert_eq!(&buf[9..12], b"com");
    assert_eq!(buf[12], 0); // root terminator
    assert_eq!(ret, 13);
}

#[test]
fn ns_name_pton_handles_root_domain() {
    let name = CString::new(".").unwrap();
    let mut buf = [0u8; 4];
    let ret = unsafe { ns_name_pton(name.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len()) };
    assert_eq!(ret, 1);
    assert_eq!(buf[0], 0); // Just root terminator.
}

#[test]
fn ns_name_pton_null_returns_error() {
    let ret = unsafe { ns_name_pton(ptr::null(), ptr::null_mut(), 0) };
    assert_eq!(ret, -1);
}

#[test]
fn resolver_name_functions_reject_tracked_unterminated_names() {
    let name = b"unterminated.example";

    unsafe {
        let raw = malloc_unterminated(name);
        assert_eq!(res_hnok(raw), 0);
        assert_eq!(res_dnok(raw), 0);
        assert_eq!(res_mailok(raw), 0);

        let mut wire = [0u8; 64];
        assert_eq!(ns_name_pton(raw, wire.as_mut_ptr().cast(), wire.len()), -1);
        assert_eq!(__ns_name_pton(raw, wire.as_mut_ptr(), wire.len()), -1);

        let mut packet = [0u8; 512];
        *__errno_location() = 0;
        let query_len = __res_mkquery(
            0,
            raw,
            1,
            1,
            ptr::null(),
            0,
            ptr::null(),
            packet.as_mut_ptr().cast(),
            packet.len() as i32,
        );
        let err = *__errno_location();
        frankenlibc_abi::malloc_abi::free(raw.cast());

        assert_eq!(query_len, -1);
        assert_eq!(err, libc::EINVAL);
    }
}

#[test]
fn resolver_output_functions_cap_tracked_short_buffers() {
    let name = CString::new("example.com").unwrap();
    let wire = make_wire_name("example.com");

    unsafe {
        let raw = malloc_tracked_zeroed_bytes(2);

        clear_errno();
        assert_eq!(ns_name_pton(name.as_ptr(), raw, 64), -1);
        assert_eq!(errno_value(), libc::EMSGSIZE);

        clear_errno();
        assert_eq!(__ns_name_pton(name.as_ptr(), raw.cast(), 64), -1);
        assert_eq!(errno_value(), libc::EMSGSIZE);

        clear_errno();
        assert_eq!(
            ns_name_ntop(wire.as_ptr().cast(), raw.cast::<c_char>(), 64),
            -1
        );
        assert_eq!(errno_value(), libc::EMSGSIZE);

        clear_errno();
        assert_eq!(__ns_name_ntop(wire.as_ptr(), raw.cast::<c_char>(), 64), -1);
        assert_eq!(errno_value(), libc::EMSGSIZE);

        clear_errno();
        assert_eq!(
            ns_name_pack(
                wire.as_ptr().cast(),
                raw,
                64,
                ptr::null_mut(),
                ptr::null_mut(),
            ),
            -1
        );

        clear_errno();
        assert_eq!(
            __ns_name_pack(wire.as_ptr(), raw.cast(), 64, ptr::null_mut(), ptr::null(),),
            -1
        );
        assert_eq!(errno_value(), libc::EMSGSIZE);

        std::ptr::write_bytes(raw.cast::<u8>(), 0, 2);
        clear_errno();
        let query_len = __res_mkquery(
            0,
            name.as_ptr(),
            1,
            1,
            ptr::null(),
            0,
            ptr::null(),
            raw,
            512,
        );
        assert_eq!(query_len, -1);
        assert_eq!(raw.cast::<u8>().read(), 0);

        frankenlibc_abi::malloc_abi::free(raw);
    }
}

#[test]
fn ns_name_ntop_decodes_wire_to_text() {
    let wire = make_wire_name("example.com");
    let mut buf = [0u8; 256];
    let ret = unsafe {
        ns_name_ntop(
            wire.as_ptr() as *const _,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    assert!(ret > 0, "ns_name_ntop returned {ret}");
    let text = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const _) };
    assert_eq!(text.to_str().unwrap(), "example.com");
}

#[test]
fn ns_name_ntop_root_outputs_dot() {
    let wire: [u8; 1] = [0]; // Root label only.
    let mut buf = [0u8; 4];
    let ret = unsafe {
        ns_name_ntop(
            wire.as_ptr() as *const _,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    assert!(ret > 0);
    assert_eq!(buf[0], b'.');
    assert_eq!(buf[1], 0);
}

#[test]
fn ns_name_ntop_null_returns_error() {
    let ret = unsafe { ns_name_ntop(ptr::null(), ptr::null_mut(), 0) };
    assert_eq!(ret, -1);
}

#[test]
fn ns_name_pton_ntop_roundtrip() {
    let name = CString::new("sub.example.org").unwrap();
    let mut wire = [0u8; 64];
    let wire_len = unsafe { ns_name_pton(name.as_ptr(), wire.as_mut_ptr() as *mut _, wire.len()) };
    assert!(wire_len > 0);

    let mut text = [0u8; 256];
    let text_len = unsafe {
        ns_name_ntop(
            wire.as_ptr() as *const _,
            text.as_mut_ptr() as *mut libc::c_char,
            text.len(),
        )
    };
    assert!(text_len > 0);
    let result = unsafe { std::ffi::CStr::from_ptr(text.as_ptr() as *const _) };
    assert_eq!(result.to_str().unwrap(), "sub.example.org");
}

#[test]
fn ns_name_skip_advances_past_name() {
    let wire = make_wire_name("foo.bar");
    let start = wire.as_ptr() as *const std::ffi::c_void;
    let eom = unsafe { wire.as_ptr().add(wire.len()) as *const std::ffi::c_void };
    let mut cur = start;
    let ret = unsafe { ns_name_skip(&mut cur, eom) };
    assert_eq!(ret, 0, "ns_name_skip should return 0 on success");
    assert_eq!(
        cur as usize - start as usize,
        wire.len(),
        "should advance past entire name"
    );
}

#[test]
fn ns_name_skip_handles_compression_pointer() {
    // Build a message with a compression pointer: \xC0\x00 (points to offset 0).
    // Place a normal name at offset 0, then a pointer at offset N.
    let mut msg = make_wire_name("test.com"); // 10 bytes: \x04test\x03com\x00
    let ptr_offset = msg.len();
    msg.push(0xC0); // Compression pointer high byte.
    msg.push(0x00); // Points to offset 0.

    let start = unsafe { msg.as_ptr().add(ptr_offset) as *const std::ffi::c_void };
    let eom = unsafe { msg.as_ptr().add(msg.len()) as *const std::ffi::c_void };
    let mut cur = start;
    let ret = unsafe { ns_name_skip(&mut cur, eom) };
    assert_eq!(ret, 0);
    assert_eq!(cur as usize - start as usize, 2, "pointer consumes 2 bytes");
}

#[test]
fn ns_name_skip_null_returns_error() {
    let ret = unsafe { ns_name_skip(ptr::null_mut(), ptr::null()) };
    assert_eq!(ret, -1);
}

#[test]
fn ns_name_unpack_decompresses_wire_name() {
    // Build a DNS message: header (12 bytes) + "example.com" wire name + pointer back to name.
    let mut msg = vec![0u8; 12]; // Fake DNS header.
    let name_offset = msg.len();
    msg.extend_from_slice(&make_wire_name("example.com"));
    let ptr_offset = msg.len();
    msg.push(0xC0);
    msg.push(name_offset as u8); // Points back to the name.

    let mut dst = [0u8; 256];
    let consumed = unsafe {
        ns_name_unpack(
            msg.as_ptr() as *const _,
            msg.as_ptr().add(msg.len()) as *const _,
            msg.as_ptr().add(ptr_offset) as *const _,
            dst.as_mut_ptr() as *mut _,
            dst.len(),
        )
    };
    assert_eq!(consumed, 2, "pointer consumes 2 bytes from source");
    // dst should contain uncompressed wire: \x07example\x03com\x00
    assert_eq!(dst[0], 7);
    assert_eq!(&dst[1..8], b"example");
    assert_eq!(dst[8], 3);
    assert_eq!(&dst[9..12], b"com");
    assert_eq!(dst[12], 0);
}

#[test]
fn ns_name_unpack_copies_uncompressed_name() {
    let wire = make_wire_name("test.org");
    let mut dst = [0u8; 64];
    let consumed = unsafe {
        ns_name_unpack(
            wire.as_ptr() as *const _,
            wire.as_ptr().add(wire.len()) as *const _,
            wire.as_ptr() as *const _,
            dst.as_mut_ptr() as *mut _,
            dst.len(),
        )
    };
    assert_eq!(consumed as usize, wire.len());
    assert_eq!(&dst[..wire.len()], &wire[..]);
}

#[test]
fn ns_name_pack_copies_labels() {
    let wire = make_wire_name("hello.world");
    let mut dst = [0u8; 64];
    let written = unsafe {
        ns_name_pack(
            wire.as_ptr() as *const _,
            dst.as_mut_ptr() as *mut _,
            dst.len() as i32,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(written as usize, wire.len());
    assert_eq!(&dst[..wire.len()], &wire[..]);
}

#[test]
fn ns_name_compress_text_to_wire() {
    let name = CString::new("dns.example.net").unwrap();
    let mut dst = [0u8; 64];
    let written = unsafe {
        ns_name_compress(
            name.as_ptr(),
            dst.as_mut_ptr() as *mut _,
            dst.len(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert!(written > 0, "ns_name_compress returned {written}");
    // Verify wire format.
    assert_eq!(dst[0], 3); // "dns"
    assert_eq!(&dst[1..4], b"dns");
    assert_eq!(dst[4], 7); // "example"
    assert_eq!(&dst[5..12], b"example");
    assert_eq!(dst[12], 3); // "net"
    assert_eq!(&dst[13..16], b"net");
    assert_eq!(dst[16], 0); // root
    assert_eq!(written, 17);
}

#[test]
fn ns_name_uncompress_wire_to_text() {
    // Reuse the unpack message with a compression pointer.
    let mut msg = vec![0u8; 12]; // Fake DNS header.
    let name_offset = msg.len();
    msg.extend_from_slice(&make_wire_name("resolv.conf"));
    let ptr_offset = msg.len();
    msg.push(0xC0);
    msg.push(name_offset as u8);

    let mut text = [0u8; 256];
    let consumed = unsafe {
        ns_name_uncompress(
            msg.as_ptr() as *const _,
            msg.as_ptr().add(msg.len()) as *const _,
            msg.as_ptr().add(ptr_offset) as *const _,
            text.as_mut_ptr() as *mut libc::c_char,
            text.len(),
        )
    };
    assert_eq!(consumed, 2);
    let result = unsafe { std::ffi::CStr::from_ptr(text.as_ptr() as *const _) };
    assert_eq!(result.to_str().unwrap(), "resolv.conf");
}

#[test]
fn ns_name_compress_uncompress_roundtrip() {
    let name = CString::new("a.b.c.d.example.com").unwrap();
    let mut wire = [0u8; 128];
    let wire_len = unsafe {
        ns_name_compress(
            name.as_ptr(),
            wire.as_mut_ptr() as *mut _,
            wire.len(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert!(wire_len > 0);

    // Build a fake message with just the wire name.
    let msg = &wire[..wire_len as usize];
    let mut text = [0u8; 256];
    let consumed = unsafe {
        ns_name_uncompress(
            msg.as_ptr() as *const _,
            msg.as_ptr().add(msg.len()) as *const _,
            msg.as_ptr() as *const _,
            text.as_mut_ptr() as *mut libc::c_char,
            text.len(),
        )
    };
    assert!(consumed > 0);
    let result = unsafe { std::ffi::CStr::from_ptr(text.as_ptr() as *const _) };
    assert_eq!(result.to_str().unwrap(), "a.b.c.d.example.com");
}

// ===========================================================================
// inet6_opt_* — IPv6 extension header option helpers (RFC 3542)
// ===========================================================================

#[test]
fn inet6_opt_init_returns_header_size() {
    // NULL buffer → returns minimum header size (2).
    let ret = unsafe { inet6_opt_init(ptr::null_mut(), 0) };
    assert_eq!(ret, 2);
}

#[test]
fn inet6_opt_init_initializes_buffer() {
    let mut buf = [0xFFu8; 16];
    let ret = unsafe { inet6_opt_init(buf.as_mut_ptr() as *mut _, buf.len() as i32) };
    assert_eq!(ret, 2);
    assert_eq!(buf[0], 0); // Next Header.
    assert_eq!(buf[1], 0); // Header Ext Length.
}

#[test]
fn inet6_opt_helpers_reject_tracked_short_buffers() {
    unsafe {
        let one_byte = malloc_tracked_zeroed_bytes(1);
        assert_eq!(inet6_opt_init(one_byte, 64), -1);
        assert_eq!(one_byte.cast::<u8>().read(), 0);
        frankenlibc_abi::malloc_abi::free(one_byte);

        let ext = malloc_tracked_zeroed_bytes(4);
        assert_eq!(inet6_opt_init(ext, 64), 2);
        let mut databuf = ptr::null_mut();
        assert_eq!(inet6_opt_append(ext, 64, 2, 0x22, 4, 2, &mut databuf), -1);
        assert!(databuf.is_null());

        let mut opt_type = 0u8;
        let mut opt_len = 0usize;
        assert_eq!(
            inet6_opt_next(ext, 64, 2, &mut opt_type, &mut opt_len, ptr::null_mut()),
            -1
        );
        frankenlibc_abi::malloc_abi::free(ext);

        let data = malloc_tracked_zeroed_bytes(1);
        let value = [1u8, 2, 3, 4];
        assert_eq!(inet6_opt_set_val(data, 0, value.as_ptr().cast(), 4), -1);
        assert_eq!(data.cast::<u8>().read(), 0);
        frankenlibc_abi::malloc_abi::free(data);

        let src = [1u8, 2, 3, 4];
        let out = malloc_tracked_zeroed_bytes(1);
        assert_eq!(
            inet6_opt_get_val(src.as_ptr().cast_mut().cast(), 0, out, 4),
            -1
        );
        assert_eq!(out.cast::<u8>().read(), 0);
        frankenlibc_abi::malloc_abi::free(out);

        let mut buf = [0u8; 64];
        let off = inet6_opt_init(buf.as_mut_ptr().cast(), buf.len() as c_int);
        let off = inet6_opt_append(
            buf.as_mut_ptr().cast(),
            buf.len() as c_int,
            off,
            0x33,
            2,
            1,
            ptr::null_mut(),
        );
        let total = inet6_opt_finish(buf.as_mut_ptr().cast(), buf.len() as c_int, off);

        let short_lenp = malloc_tracked_zeroed_bytes(1).cast::<usize>();
        let mut opt_type = 0u8;
        assert_eq!(
            inet6_opt_next(
                buf.as_mut_ptr().cast(),
                total,
                2,
                &mut opt_type,
                short_lenp,
                ptr::null_mut(),
            ),
            -1
        );
        assert_eq!(short_lenp.cast::<u8>().read(), 0);
        frankenlibc_abi::malloc_abi::free(short_lenp.cast());

        let short_databufp = malloc_tracked_zeroed_bytes(1).cast::<*mut c_void>();
        let mut opt_len = 0usize;
        assert_eq!(
            inet6_opt_find(
                buf.as_mut_ptr().cast(),
                total,
                2,
                0x33,
                &mut opt_len,
                short_databufp,
            ),
            -1
        );
        assert_eq!(short_databufp.cast::<u8>().read(), 0);
        frankenlibc_abi::malloc_abi::free(short_databufp.cast());
    }
}

#[test]
fn inet6_opt_append_set_val_finish_roundtrip() {
    let mut buf = [0u8; 64];
    // Init the header.
    let off = unsafe { inet6_opt_init(buf.as_mut_ptr() as *mut _, buf.len() as i32) };
    assert_eq!(off, 2);

    // Append an option: type 42, length 4, alignment 4.
    let mut databuf: *mut std::ffi::c_void = ptr::null_mut();
    let off2 = unsafe {
        inet6_opt_append(
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
            off,
            42,
            4,
            4,
            &mut databuf,
        )
    };
    assert!(off2 > off, "append should advance offset");
    assert!(!databuf.is_null(), "databuf should be set");

    // Set a value in the option data area.
    let val: u32 = 0xDEADBEEF;
    let set_ret = unsafe {
        inet6_opt_set_val(
            databuf,
            0,
            &val as *const u32 as *const _,
            std::mem::size_of::<u32>() as i32,
        )
    };
    assert_eq!(set_ret, 4);

    // Finish the header.
    let total = unsafe { inet6_opt_finish(buf.as_mut_ptr() as *mut _, buf.len() as i32, off2) };
    assert!(total > 0);
    assert_eq!(total % 8, 0, "total must be 8-byte aligned");
}

#[test]
fn inet6_opt_next_iterates_options() {
    let mut buf = [0u8; 64];
    let off = unsafe { inet6_opt_init(buf.as_mut_ptr() as *mut _, buf.len() as i32) };

    // Append two options with different types.
    let off2 = unsafe {
        inet6_opt_append(
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
            off,
            10,
            2,
            1,
            ptr::null_mut(),
        )
    };
    assert!(off2 > 0);

    let off3 = unsafe {
        inet6_opt_append(
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
            off2,
            20,
            3,
            1,
            ptr::null_mut(),
        )
    };
    assert!(off3 > 0);

    let total = unsafe { inet6_opt_finish(buf.as_mut_ptr() as *mut _, buf.len() as i32, off3) };
    assert!(total > 0);

    // Iterate: should find type 10 first, then type 20.
    let mut typ: u8 = 0;
    let mut len: usize = 0;
    let next1 = unsafe {
        inet6_opt_next(
            buf.as_mut_ptr() as *mut _,
            total,
            off,
            &mut typ,
            &mut len,
            ptr::null_mut(),
        )
    };
    assert!(next1 > 0);
    assert_eq!(typ, 10);

    let next2 = unsafe {
        inet6_opt_next(
            buf.as_mut_ptr() as *mut _,
            total,
            next1,
            &mut typ,
            &mut len,
            ptr::null_mut(),
        )
    };
    assert!(next2 > 0);
    assert_eq!(typ, 20);
}

#[test]
fn inet6_opt_find_locates_option_by_type() {
    let mut buf = [0u8; 64];
    let off = unsafe { inet6_opt_init(buf.as_mut_ptr() as *mut _, buf.len() as i32) };

    let off2 = unsafe {
        inet6_opt_append(
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
            off,
            10,
            2,
            1,
            ptr::null_mut(),
        )
    };
    let off3 = unsafe {
        inet6_opt_append(
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
            off2,
            20,
            3,
            1,
            ptr::null_mut(),
        )
    };
    let total = unsafe { inet6_opt_finish(buf.as_mut_ptr() as *mut _, buf.len() as i32, off3) };

    // Find type 20, skipping type 10.
    let mut len: usize = 0;
    let found = unsafe {
        inet6_opt_find(
            buf.as_mut_ptr() as *mut _,
            total,
            off,
            20,
            &mut len,
            ptr::null_mut(),
        )
    };
    assert!(found > 0, "should find type 20");
    assert_eq!(len, 3);

    // Find type 99 (doesn't exist).
    let not_found = unsafe {
        inet6_opt_find(
            buf.as_mut_ptr() as *mut _,
            total,
            off,
            99,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(not_found, -1);
}

#[test]
fn inet6_opt_get_val_reads_back_data() {
    let mut buf = [0u8; 64];
    let off = unsafe { inet6_opt_init(buf.as_mut_ptr() as *mut _, buf.len() as i32) };
    let mut databuf: *mut std::ffi::c_void = ptr::null_mut();
    let off2 = unsafe {
        inet6_opt_append(
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
            off,
            42,
            4,
            4,
            &mut databuf,
        )
    };
    assert!(off2 > 0);

    // Write value.
    let val: u32 = 0x12345678;
    unsafe { inet6_opt_set_val(databuf, 0, &val as *const _ as *const _, 4) };

    // Read it back.
    let mut readback: u32 = 0;
    let ret = unsafe { inet6_opt_get_val(databuf, 0, &mut readback as *mut _ as *mut _, 4) };
    assert_eq!(ret, 4);
    assert_eq!(readback, 0x12345678);
}

// ===========================================================================
// inet6_rth_* — IPv6 routing header (RFC 3542)
// ===========================================================================

#[test]
fn inet6_rth_space_computes_size() {
    let space = unsafe { inet6_rth_space(0, 3) };
    // Type 0: 8 header + 3 * 16 addresses = 56.
    assert_eq!(space, 56);

    // Invalid type.
    assert_eq!(unsafe { inet6_rth_space(99, 1) }, 0);

    // Negative segments.
    assert_eq!(unsafe { inet6_rth_space(0, -1) }, 0);
}

#[test]
fn inet6_rth_init_and_add_roundtrip() {
    let mut buf = [0u8; 64];
    let bp = unsafe { inet6_rth_init(buf.as_mut_ptr() as *mut _, 64, 0, 2) };
    assert!(!bp.is_null());

    // Header should be initialized.
    assert_eq!(buf[2], 0); // Routing type 0.

    // Add two addresses.
    let addr1 = [1u8; 16]; // Fake in6_addr.
    let addr2 = [2u8; 16];
    assert_eq!(unsafe { inet6_rth_add(bp, addr1.as_ptr() as *const _) }, 0);
    assert_eq!(unsafe { inet6_rth_add(bp, addr2.as_ptr() as *const _) }, 0);

    // Third add should fail (only 2 segments allocated).
    let addr3 = [3u8; 16];
    assert_eq!(unsafe { inet6_rth_add(bp, addr3.as_ptr() as *const _) }, -1);

    // Check segments.
    assert_eq!(unsafe { inet6_rth_segments(bp as *const _) }, 2);

    // Get addresses back.
    let a1 = unsafe { inet6_rth_getaddr(bp as *const _, 0) };
    assert!(!a1.is_null());
    let a1_bytes = unsafe { std::slice::from_raw_parts(a1 as *const u8, 16) };
    assert_eq!(a1_bytes, &addr1);

    let a2 = unsafe { inet6_rth_getaddr(bp as *const _, 1) };
    let a2_bytes = unsafe { std::slice::from_raw_parts(a2 as *const u8, 16) };
    assert_eq!(a2_bytes, &addr2);

    // Out of range.
    assert!(unsafe { inet6_rth_getaddr(bp as *const _, 2) }.is_null());
}

#[test]
fn inet6_rth_reverse_swaps_addresses() {
    let mut buf = [0u8; 64];
    let bp = unsafe { inet6_rth_init(buf.as_mut_ptr() as *mut _, 64, 0, 3) };
    assert!(!bp.is_null());

    let addr_a = [0xAAu8; 16];
    let addr_b = [0xBBu8; 16];
    let addr_c = [0xCCu8; 16];
    unsafe {
        inet6_rth_add(bp, addr_a.as_ptr() as *const _);
        inet6_rth_add(bp, addr_b.as_ptr() as *const _);
        inet6_rth_add(bp, addr_c.as_ptr() as *const _);
    }

    let mut out = [0u8; 64];
    let ret = unsafe { inet6_rth_reverse(bp as *const _, out.as_mut_ptr() as *mut _) };
    assert_eq!(ret, 0);

    // First address in reversed header should be addr_c.
    let r0 = unsafe { inet6_rth_getaddr(out.as_ptr() as *const _, 0) };
    let r0_bytes = unsafe { std::slice::from_raw_parts(r0 as *const u8, 16) };
    assert_eq!(r0_bytes, &addr_c);

    // Last address should be addr_a.
    let r2 = unsafe { inet6_rth_getaddr(out.as_ptr() as *const _, 2) };
    let r2_bytes = unsafe { std::slice::from_raw_parts(r2 as *const u8, 16) };
    assert_eq!(r2_bytes, &addr_a);
}

#[test]
fn inet6_rth_init_too_small_returns_null() {
    let mut buf = [0u8; 4]; // Too small for any routing header.
    let bp = unsafe { inet6_rth_init(buf.as_mut_ptr() as *mut _, 4, 0, 1) };
    assert!(bp.is_null());
}

// ===========================================================================
// Session 13: printf extension stubs
// ===========================================================================

#[test]
fn register_printf_function_returns_enosys() {
    let r = unsafe { register_printf_function(0, ptr::null_mut(), ptr::null_mut()) };
    assert_eq!(r, -1);
}

#[test]
fn register_printf_modifier_returns_enosys() {
    let r = unsafe { register_printf_modifier(ptr::null()) };
    assert_eq!(r, -1);
}

#[test]
fn register_printf_specifier_returns_enosys() {
    let r = unsafe { register_printf_specifier(0, ptr::null_mut(), ptr::null_mut()) };
    assert_eq!(r, -1);
}

#[test]
fn register_printf_type_returns_enosys() {
    let r = unsafe { register_printf_type(ptr::null_mut()) };
    assert_eq!(r, -1);
}

#[test]
fn printf_size_returns_negative() {
    let r = unsafe { printf_size(ptr::null_mut(), ptr::null(), ptr::null()) };
    assert_eq!(r, -1);
}

#[test]
fn printf_size_info_returns_zero() {
    let r = unsafe { printf_size_info(ptr::null(), 0, ptr::null_mut()) };
    assert_eq!(r, 0);
}

// ===========================================================================
// Session 13: xprt stubs (no-op)
// ===========================================================================

#[test]
fn xprt_register_noop() {
    // Just verify it doesn't crash
    unsafe { xprt_register(ptr::null_mut()) };
}

#[test]
fn xprt_unregister_noop() {
    unsafe { xprt_unregister(ptr::null_mut()) };
}

// ===========================================================================
// Session 13: NSS stubs
// ===========================================================================

#[test]
fn nss_configure_lookup_returns_zero() {
    let db = CString::new("passwd").unwrap();
    let service = CString::new("files").unwrap();
    let r = unsafe { __nss_configure_lookup(db.as_ptr(), service.as_ptr()) };
    assert_eq!(r, 0); // success (no-op)
}

#[test]
fn nss_database_lookup_returns_unavail() {
    let db = CString::new("passwd").unwrap();
    let r =
        unsafe { __nss_database_lookup(db.as_ptr(), ptr::null(), ptr::null(), ptr::null_mut()) };
    assert_eq!(r, -1); // NSS_STATUS_UNAVAIL
}

#[test]
fn nss_group_lookup_returns_unavail() {
    let name = CString::new("root").unwrap();
    let r = unsafe {
        __nss_group_lookup(
            ptr::null_mut(),
            ptr::null_mut(),
            name.as_ptr(),
            ptr::null_mut(),
        )
    };
    assert_eq!(r, -1);
}

#[test]
fn nss_hostname_digits_dots_returns_zero() {
    let name = CString::new("192.168.1.1").unwrap();
    let r = unsafe { __nss_hostname_digits_dots(name.as_ptr(), ptr::null_mut()) };
    assert_eq!(r, 0);
}

#[test]
fn nss_hosts_lookup_returns_unavail() {
    let name = CString::new("localhost").unwrap();
    let r = unsafe {
        __nss_hosts_lookup(
            ptr::null_mut(),
            ptr::null_mut(),
            name.as_ptr(),
            ptr::null_mut(),
        )
    };
    assert_eq!(r, -1);
}

#[test]
fn nss_next_returns_unavail() {
    let name = CString::new("getpwnam_r").unwrap();
    let r = unsafe { __nss_next(ptr::null_mut(), name.as_ptr(), ptr::null_mut(), 0) };
    assert_eq!(r, -1);
}

#[test]
fn nss_passwd_lookup_returns_unavail() {
    let name = CString::new("root").unwrap();
    let r = unsafe {
        __nss_passwd_lookup(
            ptr::null_mut(),
            ptr::null_mut(),
            name.as_ptr(),
            ptr::null_mut(),
        )
    };
    assert_eq!(r, -1);
}

// ===========================================================================
// Session 13: pthread_cleanup
// ===========================================================================

#[test]
fn pthread_cleanup_push_pop_executes_handler() {
    use std::sync::atomic::{AtomicI32, Ordering};
    static CALLED: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn handler(arg: *mut std::ffi::c_void) {
        let val = arg as usize as i32;
        CALLED.store(val, Ordering::SeqCst);
    }

    // Allocate a __pthread_cleanup_buffer (at least 32 bytes on x86_64)
    let mut buf = [0u8; 64];
    let buf_ptr = buf.as_mut_ptr() as *mut std::ffi::c_void;

    CALLED.store(0, Ordering::SeqCst);
    unsafe {
        _pthread_cleanup_push(
            buf_ptr,
            handler as *mut std::ffi::c_void,
            42usize as *mut std::ffi::c_void,
        );
        _pthread_cleanup_pop(buf_ptr, 1); // execute=1
    }
    assert_eq!(CALLED.load(Ordering::SeqCst), 42);
}

#[test]
fn pthread_cleanup_pop_no_execute() {
    use std::sync::atomic::{AtomicI32, Ordering};
    static CALLED2: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn handler2(arg: *mut std::ffi::c_void) {
        let _ = arg;
        CALLED2.store(99, Ordering::SeqCst);
    }

    let mut buf = [0u8; 64];
    let buf_ptr = buf.as_mut_ptr() as *mut std::ffi::c_void;

    CALLED2.store(0, Ordering::SeqCst);
    unsafe {
        _pthread_cleanup_push(buf_ptr, handler2 as *mut std::ffi::c_void, ptr::null_mut());
        _pthread_cleanup_pop(buf_ptr, 0); // execute=0
    }
    assert_eq!(CALLED2.load(Ordering::SeqCst), 0); // handler NOT called
}

#[test]
fn pthread_cleanup_push_defer_pop_restore() {
    use std::sync::atomic::{AtomicI32, Ordering};
    static CALLED3: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn handler3(arg: *mut std::ffi::c_void) {
        let val = arg as usize as i32;
        CALLED3.store(val, Ordering::SeqCst);
    }

    let mut buf = [0u8; 64];
    let buf_ptr = buf.as_mut_ptr() as *mut std::ffi::c_void;

    CALLED3.store(0, Ordering::SeqCst);
    unsafe {
        _pthread_cleanup_push_defer(
            buf_ptr,
            handler3 as *mut std::ffi::c_void,
            7usize as *mut std::ffi::c_void,
        );
        _pthread_cleanup_pop_restore(buf_ptr, 1);
    }
    assert_eq!(CALLED3.load(Ordering::SeqCst), 7);
}

// ===========================================================================
// Session 13: obstack
// ===========================================================================

// Use libc malloc/free as chunk allocators for obstack tests
unsafe extern "C" {
    fn malloc(size: usize) -> *mut std::ffi::c_void;
    fn free(ptr: *mut std::ffi::c_void);
}

#[test]
fn obstack_begin_and_allocated_p() {
    // struct obstack contains pointers, needs 8-byte alignment
    let mut obstack_buf = [0u64; 16]; // 128 bytes, naturally 8-byte aligned
    let h = obstack_buf.as_mut_ptr() as *mut std::ffi::c_void;

    let result = unsafe {
        _obstack_begin(
            h,
            4096,
            8,
            malloc as *mut std::ffi::c_void,
            free as *mut std::ffi::c_void,
        )
    };
    assert_eq!(result, 1, "obstack_begin should succeed");

    // Memory used should be positive (at least one chunk allocated)
    let mem = unsafe { _obstack_memory_used(h) };
    assert!(mem > 0, "memory_used should be > 0 after init");

    // A random stack pointer should NOT be allocated from this obstack
    let stack_var: i32 = 42;
    let r = unsafe { _obstack_allocated_p(h, &stack_var as *const i32 as *const std::ffi::c_void) };
    assert_eq!(r, 0, "stack variable should not be in obstack");

    // Clean up
    unsafe { _obstack_free(h, ptr::null_mut()) };
}

#[test]
fn obstack_newchunk_grows() {
    let mut obstack_buf = [0u64; 16]; // 8-byte aligned
    let h = obstack_buf.as_mut_ptr() as *mut std::ffi::c_void;

    let result = unsafe {
        _obstack_begin(
            h,
            64, // small chunk size to force newchunk
            8,
            malloc as *mut std::ffi::c_void,
            free as *mut std::ffi::c_void,
        )
    };
    assert_eq!(result, 1);

    // Request a new chunk larger than initial
    unsafe { _obstack_newchunk(h, 256) };

    // Memory should have grown
    let mem = unsafe { _obstack_memory_used(h) };
    assert!(mem >= 256, "memory should be at least 256 after newchunk");

    unsafe { _obstack_free(h, ptr::null_mut()) };
}

// ===========================================================================
// Session 13: __asprintf, __printf_fp, _dl_find_object
// ===========================================================================

#[test]
fn asprintf_internal_returns_enosys() {
    let mut ptr: *mut i8 = 42usize as *mut i8; // non-null sentinel
    let fmt = CString::new("hello %d").unwrap();
    let r = unsafe { __asprintf(&mut ptr, fmt.as_ptr()) };
    assert_eq!(r, -1);
    assert!(
        ptr.is_null(),
        "__asprintf should set *strp to null on failure"
    );
}

#[test]
fn printf_fp_returns_negative() {
    let r = unsafe { __printf_fp(ptr::null_mut(), ptr::null(), ptr::null()) };
    assert_eq!(r, -1);
}

#[test]
fn overflow_family_returns_enosys_defaults() {
    let r = unsafe { __overflow(ptr::null_mut(), b'A' as i32) };
    assert_eq!(r, libc::EOF);
    assert_eq!(unsafe { *__errno_location() }, libc::ENOSYS);

    let r = unsafe { __uflow(ptr::null_mut()) };
    assert_eq!(r, libc::EOF);
    assert_eq!(unsafe { *__errno_location() }, libc::ENOSYS);

    let r = unsafe { __underflow(ptr::null_mut()) };
    assert_eq!(r, libc::EOF);
    assert_eq!(unsafe { *__errno_location() }, libc::ENOSYS);
}

#[test]
fn wide_overflow_family_returns_wide_eof() {
    let r = unsafe { __woverflow(ptr::null_mut(), 'A' as i32) };
    assert_eq!(r, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::ENOSYS);

    let r = unsafe { __wuflow(ptr::null_mut()) };
    assert_eq!(r, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::ENOSYS);

    let r = unsafe { __wunderflow(ptr::null_mut()) };
    assert_eq!(r, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::ENOSYS);
}

// ===========================================================================
// res_* public forwarders (delegate to native __res_* implementations)
// ===========================================================================

#[test]
fn res_mkquery_null_returns_error() {
    // res_mkquery with null dname should return -1 (via __res_mkquery GCT)
    let r = unsafe {
        res_mkquery(
            0,
            ptr::null(),
            1, // C_IN
            1, // T_A
            ptr::null(),
            0,
            ptr::null(),
            ptr::null_mut(),
            0,
        )
    };
    assert!(r <= 0);
}

#[test]
fn res_nmkquery_null_statp_returns_error() {
    let r = unsafe {
        res_nmkquery(
            ptr::null_mut(),
            0,
            ptr::null(),
            1,
            1,
            ptr::null(),
            0,
            ptr::null(),
            ptr::null_mut(),
            0,
        )
    };
    assert!(r <= 0);
}

#[test]
fn res_nquery_null_statp_returns_error() {
    let r = unsafe { res_nquery(ptr::null_mut(), ptr::null(), 1, 1, ptr::null_mut(), 0) };
    assert!(r <= 0);
}

#[test]
fn res_nquerydomain_null_returns_error() {
    let r = unsafe {
        res_nquerydomain(
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            1,
            1,
            ptr::null_mut(),
            0,
        )
    };
    assert!(r <= 0);
}

#[test]
fn res_nsearch_null_returns_error() {
    let r = unsafe { res_nsearch(ptr::null_mut(), ptr::null(), 1, 1, ptr::null_mut(), 0) };
    assert!(r <= 0);
}

#[test]
fn res_nsend_null_returns_error() {
    let r = unsafe { res_nsend(ptr::null_mut(), ptr::null(), 0, ptr::null_mut(), 0) };
    assert!(r <= 0);
}

#[test]
fn res_querydomain_null_returns_error() {
    let r = unsafe { res_querydomain(ptr::null(), ptr::null(), 1, 1, ptr::null_mut(), 0) };
    assert!(r <= 0);
}

#[test]
fn res_send_null_returns_error() {
    let r = unsafe { res_send(ptr::null(), 0, ptr::null_mut(), 0) };
    assert!(r <= 0);
}

// ===========================================================================
// Session 14: nativized DNS + f128 tests
// ===========================================================================

#[test]
fn res_mkquery_builds_valid_query() {
    let name = CString::new("example.com").unwrap();
    let mut buf = [0u8; 512];
    let len = unsafe {
        __res_mkquery(
            0, // QUERY
            name.as_ptr(),
            1, // C_IN
            1, // T_A
            ptr::null(),
            0,
            ptr::null(),
            buf.as_mut_ptr().cast(),
            512,
        )
    };
    // Minimum: 12 (header) + 13 (example.com encoded) + 4 (qtype+qclass) = 29
    assert!(len >= 29, "expected >= 29 bytes, got {len}");
    // QR bit should be 0 (query), RD bit should be 1
    assert_eq!(buf[2] & 0x80, 0, "QR should be 0 (query)");
    assert_eq!(buf[2] & 0x01, 1, "RD should be 1");
    // QDCOUNT should be 1
    assert_eq!(u16::from_be_bytes([buf[4], buf[5]]), 1);
}

#[test]
fn res_mkquery_unsupported_op_returns_error() {
    let name = CString::new("test.com").unwrap();
    let mut buf = [0u8; 512];
    let len = unsafe {
        __res_mkquery(
            1, // IQUERY — unsupported
            name.as_ptr(),
            1,
            1,
            ptr::null(),
            0,
            ptr::null(),
            buf.as_mut_ptr().cast(),
            512,
        )
    };
    assert_eq!(len, -1);
}

#[test]
fn res_mkquery_buffer_too_small_returns_error() {
    let name = CString::new("example.com").unwrap();
    let mut buf = [0u8; 10]; // too small
    let len = unsafe {
        __res_mkquery(
            0,
            name.as_ptr(),
            1,
            1,
            ptr::null(),
            0,
            ptr::null(),
            buf.as_mut_ptr().cast(),
            10,
        )
    };
    assert_eq!(len, -1);
}

#[test]
fn res_send_null_msg_returns_error() {
    let r = unsafe { __res_send(ptr::null(), 0, ptr::null_mut(), 0) };
    assert_eq!(r, -1);
}

#[test]
fn res_state_returns_non_null() {
    let state = unsafe { __res_state() };
    assert!(
        !state.is_null(),
        "__res_state should return non-null TLS pointer"
    );
    // Calling twice in the same thread should return the same pointer.
    let state2 = unsafe { __res_state() };
    assert_eq!(
        state, state2,
        "__res_state should be stable within a thread"
    );
}

#[test]
fn strtof128_internal_parses_number() {
    let input = CString::new("3.25").unwrap();
    let mut endptr: *mut libc::c_char = ptr::null_mut();
    let val = unsafe { __strtof128_internal(input.as_ptr(), &mut endptr, 0) };
    assert!((val - 3.25).abs() < 1e-10);
    assert!(!endptr.is_null());
}

#[test]
fn strtof128_internal_null_returns_zero() {
    let input = CString::new("").unwrap();
    let mut endptr: *mut libc::c_char = ptr::null_mut();
    let val = unsafe { __strtof128_internal(input.as_ptr(), &mut endptr, 0) };
    assert_eq!(val, 0.0);
}

#[test]
fn wcstof128_internal_parses_number() {
    let input: Vec<i32> = "1.625\0".chars().map(|c| c as i32).collect();
    let mut endptr: *mut i32 = ptr::null_mut();
    let val = unsafe { __wcstof128_internal(input.as_ptr(), &mut endptr, 0) };
    assert!((val - 1.625).abs() < 1e-10);
}

#[test]
fn dl_find_object_returns_not_found() {
    let r = unsafe { _dl_find_object(ptr::null_mut(), ptr::null_mut()) };
    assert_eq!(r, -1);
}

// ===========================================================================
// Session 19: Native DNS name functions (__ns_name_* batch)
// ===========================================================================

#[test]
fn ns_name_ntop_converts_wire_to_dotted() {
    // Wire format: \x07example\x03com\x00
    let wire: &[u8] = &[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ];
    let mut buf = [0i8; 256];
    let ret = unsafe { __ns_name_ntop(wire.as_ptr(), buf.as_mut_ptr(), 256) };
    assert!(ret > 0, "ns_name_ntop should return positive length");
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(s.to_str().unwrap(), "example.com");
}

#[test]
fn ns_name_ntop_root_domain() {
    let wire: &[u8] = &[0]; // root domain
    let mut buf = [0i8; 256];
    let ret = unsafe { __ns_name_ntop(wire.as_ptr(), buf.as_mut_ptr(), 256) };
    assert!(ret > 0);
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(s.to_str().unwrap(), ".");
}

#[test]
fn ns_name_pton_converts_dotted_to_wire() {
    let name = CString::new("example.com").unwrap();
    let mut buf = [0u8; 256];
    let ret = unsafe { __ns_name_pton(name.as_ptr(), buf.as_mut_ptr(), 256) };
    assert!(ret >= 0, "ns_name_pton should succeed");
    // Verify wire format: \x07example\x03com\x00
    assert_eq!(buf[0], 7); // "example" length
    assert_eq!(&buf[1..8], b"example");
    assert_eq!(buf[8], 3); // "com" length
    assert_eq!(&buf[9..12], b"com");
    assert_eq!(buf[12], 0); // terminator
}

#[test]
fn ns_name_pton_fully_qualified() {
    let name = CString::new("example.com.").unwrap();
    let mut buf = [0u8; 256];
    let ret = unsafe { __ns_name_pton(name.as_ptr(), buf.as_mut_ptr(), 256) };
    assert_eq!(
        ret, 1,
        "trailing dot means fully qualified, should return 1"
    );
}

#[test]
fn ns_name_unpack_simple() {
    // Message containing an uncompressed name: \x07example\x03com\x00
    let msg: &[u8] = &[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ];
    let mut buf = [0u8; 255];
    let ret = unsafe {
        __ns_name_unpack(
            msg.as_ptr(),
            msg.as_ptr().add(msg.len()),
            msg.as_ptr(),
            buf.as_mut_ptr(),
            255,
        )
    };
    assert!(ret > 0, "ns_name_unpack should return consumed bytes");
    assert_eq!(ret as usize, msg.len());
}

#[test]
fn ns_name_unpack_with_compression() {
    // Simulate a message with a compression pointer.
    // bytes 0-12: \x07example\x03com\x00  (the name)
    // bytes 13-14: \xC0\x00  (compression pointer to offset 0)
    let msg: &[u8] = &[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0xC0, 0x00,
    ];
    let mut buf = [0u8; 255];
    let ret = unsafe {
        __ns_name_unpack(
            msg.as_ptr(),
            msg.as_ptr().add(msg.len()),
            msg.as_ptr().add(13), // start at compression pointer
            buf.as_mut_ptr(),
            255,
        )
    };
    assert!(ret > 0, "ns_name_unpack should follow compression pointer");
    assert_eq!(ret, 2, "should consume 2 bytes (the compression pointer)");
    // Result should be the uncompressed name
    assert_eq!(buf[0], 7);
    assert_eq!(&buf[1..8], b"example");
}

#[test]
fn ns_name_pack_simple() {
    // Pack an uncompressed wire-format name
    let src: &[u8] = &[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ];
    let mut dst = [0u8; 256];
    let ret = unsafe {
        __ns_name_pack(
            src.as_ptr(),
            dst.as_mut_ptr(),
            256,
            ptr::null_mut(),
            ptr::null(),
        )
    };
    assert_eq!(ret as usize, src.len());
    assert_eq!(&dst[..src.len()], src);
}

#[test]
fn ns_name_skip_uncompressed() {
    let msg: &[u8] = &[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 42,
    ];
    let mut ptr: *const u8 = msg.as_ptr();
    let eom = unsafe { msg.as_ptr().add(msg.len()) };
    let ret = unsafe { __ns_name_skip(&mut ptr, eom) };
    assert_eq!(ret, 0, "ns_name_skip should succeed");
    // ptr should now point past the name (to the 42 byte)
    assert_eq!(unsafe { ptr.offset_from(msg.as_ptr()) } as usize, 13);
}

#[test]
fn ns_name_skip_compressed() {
    let msg: &[u8] = &[0xC0, 0x00, 42]; // compression pointer + trailing data
    let mut ptr: *const u8 = msg.as_ptr();
    let eom = unsafe { msg.as_ptr().add(msg.len()) };
    let ret = unsafe { __ns_name_skip(&mut ptr, eom) };
    assert_eq!(ret, 0);
    assert_eq!(unsafe { ptr.offset_from(msg.as_ptr()) } as usize, 2);
}

#[test]
fn ns_name_uncompress_roundtrip() {
    let msg: &[u8] = &[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ];
    let mut buf = [0i8; 256];
    let ret = unsafe {
        __ns_name_uncompress(
            msg.as_ptr(),
            msg.as_ptr().add(msg.len()),
            msg.as_ptr(),
            buf.as_mut_ptr(),
            256,
        )
    };
    assert!(ret > 0);
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(s.to_str().unwrap(), "example.com");
}

#[test]
fn ns_name_compress_roundtrip() {
    let name = CString::new("test.example.com").unwrap();
    let mut wire = [0u8; 256];
    let ret = unsafe {
        __ns_name_compress(
            name.as_ptr(),
            wire.as_mut_ptr(),
            256,
            ptr::null_mut(),
            ptr::null(),
        )
    };
    assert!(ret > 0, "ns_name_compress should succeed");
    // Now uncompress to verify roundtrip
    let mut dotted = [0i8; 256];
    let ret2 = unsafe {
        __ns_name_uncompress(
            wire.as_ptr(),
            wire.as_ptr().add(ret as usize),
            wire.as_ptr(),
            dotted.as_mut_ptr(),
            256,
        )
    };
    assert!(ret2 > 0);
    let s = unsafe { std::ffi::CStr::from_ptr(dotted.as_ptr()) };
    assert_eq!(s.to_str().unwrap(), "test.example.com");
}

#[test]
fn ns_name_uncompressed_p_returns_true_for_simple() {
    let msg: &[u8] = &[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ];
    let ret = unsafe {
        __ns_name_uncompressed_p(msg.as_ptr(), msg.as_ptr().add(msg.len()), msg.as_ptr())
    };
    assert_eq!(ret, 1, "simple name should be uncompressed");
}

#[test]
fn ns_name_uncompressed_p_returns_false_for_pointer() {
    let msg: &[u8] = &[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0xC0, 0x00,
    ];
    let ret = unsafe {
        __ns_name_uncompressed_p(
            msg.as_ptr(),
            msg.as_ptr().add(msg.len()),
            msg.as_ptr().add(13), // points to compression pointer
        )
    };
    assert_eq!(ret, 0, "compression pointer should be detected");
}

#[test]
fn ns_samename_same_names() {
    let a = CString::new("example.com").unwrap();
    let b = CString::new("example.com").unwrap();
    assert_eq!(unsafe { __ns_samename(a.as_ptr(), b.as_ptr()) }, 1);
}

#[test]
fn ns_samename_case_insensitive() {
    let a = CString::new("Example.COM").unwrap();
    let b = CString::new("example.com").unwrap();
    assert_eq!(unsafe { __ns_samename(a.as_ptr(), b.as_ptr()) }, 1);
}

#[test]
fn ns_samename_trailing_dot() {
    let a = CString::new("example.com.").unwrap();
    let b = CString::new("example.com").unwrap();
    assert_eq!(unsafe { __ns_samename(a.as_ptr(), b.as_ptr()) }, 1);
}

#[test]
fn ns_samename_different_names() {
    let a = CString::new("example.com").unwrap();
    let b = CString::new("example.org").unwrap();
    assert_eq!(unsafe { __ns_samename(a.as_ptr(), b.as_ptr()) }, 0);
}

// ===========================================================================
// Session 19: __twalk_r (native reentrant tree walk)
// ===========================================================================

#[test]
fn twalk_r_counts_nodes() {
    use frankenlibc_abi::search_abi::{tdelete, tsearch};
    use std::os::raw::c_void;

    unsafe extern "C" fn cmp(a: *const c_void, b: *const c_void) -> libc::c_int {
        let a = a as usize;
        let b = b as usize;
        (a > b) as libc::c_int - (a < b) as libc::c_int
    }

    unsafe extern "C" fn counter(
        _node: *const c_void,
        visit: libc::c_int,
        _level: libc::c_int,
        closure: *mut c_void,
    ) {
        // Count only on preorder (0) or leaf (3), visiting each node exactly once
        if visit == 0 || visit == 3 {
            unsafe {
                let cnt = &mut *(closure as *mut i32);
                *cnt += 1;
            }
        }
    }

    let mut root: *mut c_void = ptr::null_mut();
    // Insert 5 values
    for i in 1..=5 {
        unsafe { tsearch(i as *const c_void, &mut root, cmp) };
    }

    let mut count: i32 = 0;
    unsafe {
        __twalk_r(root, counter, &mut count as *mut i32 as *mut c_void);
    }
    assert_eq!(count, 5, "twalk_r should visit all 5 nodes");

    // Cleanup
    for i in 1..=5 {
        unsafe { tdelete(i as *const c_void, &mut root, cmp) };
    }
}

// ===========================================================================
// Session 19: __mktemp (native)
// ===========================================================================

#[test]
fn mktemp_replaces_x_chars() {
    let mut template: Vec<u8> = b"/tmp/test_XXXXXX\0".to_vec();
    let result = unsafe { __mktemp(template.as_mut_ptr() as *mut libc::c_char) };
    assert!(!result.is_null());
    // Verify the X chars were replaced
    let s = unsafe { std::ffi::CStr::from_ptr(result) };
    let name = s.to_str().unwrap();
    assert!(name.starts_with("/tmp/test_"));
    assert!(!name.contains("XXXXXX"), "X chars should be replaced");
}

#[test]
fn mktemp_rejects_short_template() {
    let mut template: Vec<u8> = b"short\0".to_vec();
    let result = unsafe { __mktemp(template.as_mut_ptr() as *mut libc::c_char) };
    assert!(!result.is_null());
    // First byte should be 0 (error)
    assert_eq!(unsafe { *result } as u8, 0);
}

#[test]
fn internal_stdio_aliases_follow_native_seek_and_tell_contracts() {
    let stream = unsafe { frankenlibc_abi::stdio_abi::tmpfile() };
    assert!(!stream.is_null());

    let data = b"0123456789";
    let written =
        unsafe { frankenlibc_abi::stdio_abi::fwrite(data.as_ptr().cast(), 1, data.len(), stream) };
    assert_eq!(written, data.len());

    assert_eq!(unsafe { __fseeko64(stream, 7, libc::SEEK_SET) }, 0);
    assert_eq!(unsafe { __ftello64(stream) }, 7);

    assert_eq!(
        unsafe { __fseeko64(std::ptr::null_mut(), 0, libc::SEEK_SET) },
        -1
    );
    assert_eq!(unsafe { __ftello64(std::ptr::null_mut()) }, -1);

    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(stream) }, 0);
}

#[test]
fn resolv_context_native_shim_reuses_tls_context_and_preserves_errno() {
    let ctx1 = unsafe { __resolv_context_get() };
    assert!(!ctx1.is_null());

    let ctx2 = unsafe { __resolv_context_get() };
    assert_eq!(ctx1, ctx2);

    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::EINTR };
    unsafe { *frankenlibc_abi::resolv_abi::__h_errno_location() = 17 };
    unsafe { __resolv_context_put(ctx2) };
    assert_eq!(
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
        libc::EINTR
    );
    assert_eq!(
        unsafe { *frankenlibc_abi::resolv_abi::__h_errno_location() },
        17
    );

    let ctx3 = unsafe { __resolv_context_get_preinit() };
    assert_eq!(ctx1, ctx3);

    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::EAGAIN };
    unsafe { *frankenlibc_abi::resolv_abi::__h_errno_location() = 23 };
    unsafe { __resolv_context_put(ctx3) };
    assert_eq!(
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
        libc::EAGAIN
    );
    assert_eq!(
        unsafe { *frankenlibc_abi::resolv_abi::__h_errno_location() },
        23
    );

    unsafe { __resolv_context_put(ctx1) };
}

#[test]
fn resolv_context_override_and_freeres_follow_local_contract() {
    let base = unsafe { __resolv_context_get() };
    assert!(!base.is_null());

    let mut override_state = [0u8; 640];
    let override_ctx = unsafe { __resolv_context_get_override(override_state.as_mut_ptr().cast()) };
    assert!(!override_ctx.is_null());
    assert_ne!(base, override_ctx);

    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::ERANGE };
    unsafe { *frankenlibc_abi::resolv_abi::__h_errno_location() = 29 };
    unsafe { __resolv_context_freeres() };
    assert_eq!(
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
        libc::ERANGE
    );
    assert_eq!(
        unsafe { *frankenlibc_abi::resolv_abi::__h_errno_location() },
        29
    );

    let fresh = unsafe { __resolv_context_get() };
    assert!(!fresh.is_null());
    unsafe { __resolv_context_put(fresh) };
}

#[test]
fn resolv_context_override_rejects_null_state() {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let ctx = unsafe { __resolv_context_get_override(std::ptr::null_mut()) };
    assert!(ctx.is_null());
    assert_eq!(
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
        libc::EINVAL
    );
}

// ===========================================================================
// Session 19: __shm_get_name (native)
// ===========================================================================

#[test]
fn shm_get_name_constructs_path() {
    let name = CString::new("test_segment").unwrap();
    let mut buf = [0u8; 256];
    let ret = unsafe {
        __shm_get_name(
            buf.as_mut_ptr() as *mut std::os::raw::c_void,
            256,
            name.as_ptr(),
        )
    };
    assert_eq!(ret, 0, "should succeed");
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    assert_eq!(s.to_str().unwrap(), "/dev/shm/test_segment");
}

#[test]
fn shm_get_name_rejects_slash() {
    let name = CString::new("bad/name").unwrap();
    let mut buf = [0u8; 256];
    let ret = unsafe {
        __shm_get_name(
            buf.as_mut_ptr() as *mut std::os::raw::c_void,
            256,
            name.as_ptr(),
        )
    };
    assert_eq!(ret, libc::EINVAL);
}

#[test]
fn shm_get_name_rejects_dot() {
    let name = CString::new(".").unwrap();
    let mut buf = [0u8; 256];
    let ret = unsafe {
        __shm_get_name(
            buf.as_mut_ptr() as *mut std::os::raw::c_void,
            256,
            name.as_ptr(),
        )
    };
    assert_eq!(ret, libc::EINVAL);
}

#[test]
fn shm_get_name_rejects_dotdot() {
    let name = CString::new("..").unwrap();
    let mut buf = [0u8; 256];
    let ret = unsafe {
        __shm_get_name(
            buf.as_mut_ptr() as *mut std::os::raw::c_void,
            256,
            name.as_ptr(),
        )
    };
    assert_eq!(ret, libc::EINVAL);
}

// ===========================================================================
// Session 19: File change detection (native)
// ===========================================================================

#[test]
fn file_change_detection_for_path_works() {
    // Use /etc/hostname which should exist on Linux
    let path = CString::new("/etc/hostname").unwrap();
    let mut result = [0u64; 8]; // 8-byte aligned for FileChangeDetection
    let ret = unsafe {
        __file_change_detection_for_path(
            result.as_mut_ptr() as *mut std::os::raw::c_void,
            path.as_ptr(),
        )
    };
    assert_eq!(ret, 1, "should succeed for existing file");
}

#[test]
fn file_change_detection_for_nonexistent() {
    let path = CString::new("/nonexistent_file_12345").unwrap();
    let mut result = [0u64; 8];
    let ret = unsafe {
        __file_change_detection_for_path(
            result.as_mut_ptr() as *mut std::os::raw::c_void,
            path.as_ptr(),
        )
    };
    assert_eq!(ret, 0, "should fail for nonexistent file");
}

#[test]
fn file_is_unchanged_same_data() {
    let path = CString::new("/etc/hostname").unwrap();
    let mut det1 = [0u64; 8];
    let mut det2 = [0u64; 8];
    unsafe {
        __file_change_detection_for_path(
            det1.as_mut_ptr() as *mut std::os::raw::c_void,
            path.as_ptr(),
        );
        __file_change_detection_for_path(
            det2.as_mut_ptr() as *mut std::os::raw::c_void,
            path.as_ptr(),
        );
    }
    let unchanged = unsafe {
        __file_is_unchanged(
            det1.as_ptr() as *const std::os::raw::c_void,
            det2.as_ptr() as *const std::os::raw::c_void,
        )
    };
    assert_eq!(unchanged, 1, "same file should be unchanged");
}

#[test]
fn file_change_detection_for_stat_works() {
    let path = CString::new("/etc/hostname").unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::stat(path.as_ptr(), &mut st) };
    let mut result = [0u64; 8];
    let ret = unsafe {
        __file_change_detection_for_stat(
            result.as_mut_ptr() as *mut std::os::raw::c_void,
            &st as *const libc::stat as *const std::os::raw::c_void,
        )
    };
    assert_eq!(ret, 1, "should succeed");
}

// ===========================================================================
// Session 19: __copy_grp and __merge_grp (native)
// ===========================================================================

#[test]
fn copy_grp_copies_all_fields() {
    let name = CString::new("testgrp").unwrap();
    let passwd = CString::new("x").unwrap();
    let mem1 = CString::new("alice").unwrap();
    let mem2 = CString::new("bob").unwrap();
    let mut members: [*mut c_char; 3] = [
        mem1.as_ptr() as *mut c_char,
        mem2.as_ptr() as *mut c_char,
        std::ptr::null_mut(),
    ];
    let src = libc::group {
        gr_name: name.as_ptr() as *mut c_char,
        gr_passwd: passwd.as_ptr() as *mut c_char,
        gr_gid: 1234,
        gr_mem: members.as_mut_ptr(),
    };
    let mut dest: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; 512];
    let mut result: *mut std::os::raw::c_void = std::ptr::null_mut();
    let ret = unsafe {
        __copy_grp(
            &mut dest as *mut libc::group as *mut std::os::raw::c_void,
            &src as *const libc::group as *const std::os::raw::c_void,
            buf.as_mut_ptr() as *mut c_char,
            512,
            &mut result,
        )
    };
    assert_eq!(ret, 0, "copy should succeed");
    assert!(!result.is_null());
    assert_eq!(dest.gr_gid, 1234);
    unsafe {
        assert_eq!(CStr::from_ptr(dest.gr_name).to_str().unwrap(), "testgrp");
        assert_eq!(CStr::from_ptr(dest.gr_passwd).to_str().unwrap(), "x");
        assert!(!dest.gr_mem.is_null());
        assert_eq!(
            CStr::from_ptr(*dest.gr_mem.add(0)).to_str().unwrap(),
            "alice"
        );
        assert_eq!(CStr::from_ptr(*dest.gr_mem.add(1)).to_str().unwrap(), "bob");
        assert!((*dest.gr_mem.add(2)).is_null());
    }
}

#[test]
fn copy_grp_erange_on_small_buffer() {
    let name = CString::new("testgrp").unwrap();
    let passwd = CString::new("x").unwrap();
    let mut members: [*mut c_char; 1] = [std::ptr::null_mut()];
    let src = libc::group {
        gr_name: name.as_ptr() as *mut c_char,
        gr_passwd: passwd.as_ptr() as *mut c_char,
        gr_gid: 1,
        gr_mem: members.as_mut_ptr(),
    };
    let mut dest: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; 4]; // way too small
    let mut result: *mut std::os::raw::c_void = std::ptr::null_mut();
    let ret = unsafe {
        __copy_grp(
            &mut dest as *mut libc::group as *mut std::os::raw::c_void,
            &src as *const libc::group as *const std::os::raw::c_void,
            buf.as_mut_ptr() as *mut c_char,
            4,
            &mut result,
        )
    };
    assert_eq!(ret, libc::ERANGE, "should fail with ERANGE on tiny buffer");
}

#[test]
fn putgrent_rejects_tracked_unterminated_group_fields() {
    let raw_name = unsafe { malloc_unterminated(b"unterminated-group") };
    let mut stream_buf: *mut c_char = std::ptr::null_mut();
    let mut stream_len: usize = 0;
    let stream =
        unsafe { frankenlibc_abi::stdio_abi::open_memstream(&mut stream_buf, &mut stream_len) };
    if stream.is_null() {
        unsafe { frankenlibc_abi::malloc_abi::free(raw_name.cast()) };
        return;
    }

    let mut members: [*mut c_char; 1] = [std::ptr::null_mut()];
    let entry = libc::group {
        gr_name: raw_name,
        gr_passwd: std::ptr::null_mut(),
        gr_gid: 42,
        gr_mem: members.as_mut_ptr(),
    };

    unsafe {
        *__errno_location() = 0;
        let rc = putgrent(&entry as *const libc::group as *const _, stream);
        let err = *__errno_location();
        let close_rc = frankenlibc_abi::stdio_abi::fclose(stream);
        frankenlibc_abi::malloc_abi::free(raw_name.cast());
        if !stream_buf.is_null() {
            frankenlibc_abi::malloc_abi::free(stream_buf.cast());
        }

        assert_eq!(rc, -1);
        assert_eq!(err, libc::EINVAL);
        assert_eq!(close_rc, 0);
    }
}

#[test]
fn putgrent_rejects_tracked_unterminated_member_list() {
    let name = CString::new("testgrp").unwrap();
    let member = CString::new("alice").unwrap();
    let members = unsafe {
        frankenlibc_abi::malloc_abi::malloc(std::mem::size_of::<*mut c_char>())
            .cast::<*mut c_char>()
    };
    assert!(!members.is_null());
    unsafe { *members = member.as_ptr() as *mut c_char };

    let mut stream_buf: *mut c_char = std::ptr::null_mut();
    let mut stream_len: usize = 0;
    let stream =
        unsafe { frankenlibc_abi::stdio_abi::open_memstream(&mut stream_buf, &mut stream_len) };
    if stream.is_null() {
        unsafe { frankenlibc_abi::malloc_abi::free(members.cast()) };
        return;
    }

    let entry = libc::group {
        gr_name: name.as_ptr() as *mut c_char,
        gr_passwd: std::ptr::null_mut(),
        gr_gid: 42,
        gr_mem: members,
    };

    unsafe {
        *__errno_location() = 0;
        let rc = putgrent(&entry as *const libc::group as *const _, stream);
        let err = *__errno_location();
        let close_rc = frankenlibc_abi::stdio_abi::fclose(stream);
        frankenlibc_abi::malloc_abi::free(members.cast());
        if !stream_buf.is_null() {
            frankenlibc_abi::malloc_abi::free(stream_buf.cast());
        }

        assert_eq!(rc, -1);
        assert_eq!(err, libc::EINVAL);
        assert_eq!(close_rc, 0);
    }
}

#[test]
fn putpwent_rejects_tracked_unterminated_passwd_fields() {
    let raw_name = unsafe { malloc_unterminated(b"unterminated-user") };
    let mut stream_buf: *mut c_char = std::ptr::null_mut();
    let mut stream_len: usize = 0;
    let stream =
        unsafe { frankenlibc_abi::stdio_abi::open_memstream(&mut stream_buf, &mut stream_len) };
    if stream.is_null() {
        unsafe { frankenlibc_abi::malloc_abi::free(raw_name.cast()) };
        return;
    }

    let entry = libc::passwd {
        pw_name: raw_name,
        pw_passwd: std::ptr::null_mut(),
        pw_uid: 1000,
        pw_gid: 1000,
        pw_gecos: std::ptr::null_mut(),
        pw_dir: std::ptr::null_mut(),
        pw_shell: std::ptr::null_mut(),
    };

    unsafe {
        *__errno_location() = 0;
        let rc = putpwent(&entry as *const libc::passwd as *const _, stream);
        let err = *__errno_location();
        let close_rc = frankenlibc_abi::stdio_abi::fclose(stream);
        frankenlibc_abi::malloc_abi::free(raw_name.cast());
        if !stream_buf.is_null() {
            frankenlibc_abi::malloc_abi::free(stream_buf.cast());
        }

        assert_eq!(rc, -1);
        assert_eq!(err, libc::EINVAL);
        assert_eq!(close_rc, 0);
    }
}

#[test]
fn getpw_preserves_non_utf8_passwd_field_bytes() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tmp/glibc-internal-tests");
    std::fs::create_dir_all(&dir).expect("create test temp dir");
    let path = dir.join(format!("getpw-nonutf8-{}.passwd", std::process::id()));
    let mut content = b"raw:x:4242:7:name-".to_vec();
    content.push(0xff);
    content.extend_from_slice(b":/home/raw:/bin/sh\n");
    std::fs::write(&path, content).expect("write test passwd file");

    unsafe {
        std::env::set_var("FRANKENLIBC_PASSWD_PATH", &path);
    }
    let mut buf = [0 as c_char; 128];
    let rc = unsafe { getpw(4242, buf.as_mut_ptr()) };
    unsafe {
        std::env::remove_var("FRANKENLIBC_PASSWD_PATH");
    }

    assert_eq!(rc, 0);
    let nul = buf
        .iter()
        .position(|&b| b == 0)
        .expect("getpw output should be nul-terminated");
    let bytes: Vec<u8> = buf[..nul].iter().map(|&b| b as u8).collect();
    assert_eq!(bytes, b"raw:x:4242:7:name-\xff:/home/raw:/bin/sh");
}

#[test]
fn sgetspent_r_rejects_tracked_unterminated_shadow_line() {
    let raw_line = unsafe { malloc_unterminated(b"root:*:1::::::") };
    let mut spbuf: libc::spwd = unsafe { std::mem::zeroed() };
    let mut storage = [0 as c_char; 64];
    let mut result: *mut std::ffi::c_void = std::ptr::null_mut();

    unsafe {
        let rc = sgetspent_r(
            raw_line,
            &mut spbuf as *mut libc::spwd as *mut std::ffi::c_void,
            storage.as_mut_ptr(),
            storage.len(),
            &mut result,
        );
        frankenlibc_abi::malloc_abi::free(raw_line.cast());

        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
    }
}

#[test]
fn merge_grp_adds_new_members() {
    let name = CString::new("grp").unwrap();
    let passwd = CString::new("x").unwrap();
    let alice = CString::new("alice").unwrap();
    let bob = CString::new("bob").unwrap();
    let charlie = CString::new("charlie").unwrap();

    // dest has alice
    let mut dest_members: [*mut c_char; 2] = [alice.as_ptr() as *mut c_char, std::ptr::null_mut()];
    let mut dest = libc::group {
        gr_name: name.as_ptr() as *mut c_char,
        gr_passwd: passwd.as_ptr() as *mut c_char,
        gr_gid: 100,
        gr_mem: dest_members.as_mut_ptr(),
    };

    // src has alice (dup) and bob and charlie (new)
    let mut src_members: [*mut c_char; 4] = [
        alice.as_ptr() as *mut c_char,
        bob.as_ptr() as *mut c_char,
        charlie.as_ptr() as *mut c_char,
        std::ptr::null_mut(),
    ];
    let src = libc::group {
        gr_name: name.as_ptr() as *mut c_char,
        gr_passwd: passwd.as_ptr() as *mut c_char,
        gr_gid: 100,
        gr_mem: src_members.as_mut_ptr(),
    };

    let mut buf = [0u8; 1024];
    let mut result: *mut std::os::raw::c_void = std::ptr::null_mut();
    let ret = unsafe {
        __merge_grp(
            &mut dest as *mut libc::group as *mut std::os::raw::c_void,
            &src as *const libc::group as *const std::os::raw::c_void,
            buf.as_mut_ptr() as *mut c_char,
            1024,
            &mut result,
        )
    };
    assert_eq!(ret, 0, "merge should succeed");
    assert!(!result.is_null());

    // Collect merged members
    let mut merged = Vec::new();
    unsafe {
        let mut i = 0;
        while !(*dest.gr_mem.add(i)).is_null() {
            merged.push(
                CStr::from_ptr(*dest.gr_mem.add(i))
                    .to_str()
                    .unwrap()
                    .to_string(),
            );
            i += 1;
        }
    }
    assert_eq!(merged.len(), 3, "should have 3 unique members");
    assert!(merged.contains(&"alice".to_string()));
    assert!(merged.contains(&"bob".to_string()));
    assert!(merged.contains(&"charlie".to_string()));
}

// ===========================================================================
// __inet_aton_exact — strict inet_aton (no trailing garbage)
// ===========================================================================

#[test]
fn test_inet_aton_exact_basic() {
    let mut addr: u32 = 0;
    let rc = unsafe { __inet_aton_exact(c"192.168.1.1".as_ptr(), &mut addr) };
    assert_eq!(rc, 1);
    assert_eq!(addr.to_ne_bytes(), [192, 168, 1, 1]);
}

#[test]
fn test_inet_aton_exact_loopback() {
    let mut addr: u32 = 0;
    let rc = unsafe { __inet_aton_exact(c"127.0.0.1".as_ptr(), &mut addr) };
    assert_eq!(rc, 1);
    assert_eq!(addr.to_ne_bytes(), [127, 0, 0, 1]);
}

#[test]
fn test_inet_aton_exact_zero() {
    let mut addr: u32 = 0xFFFF_FFFF;
    let rc = unsafe { __inet_aton_exact(c"0.0.0.0".as_ptr(), &mut addr) };
    assert_eq!(rc, 1);
    assert_eq!(addr, 0);
}

#[test]
fn test_inet_aton_exact_broadcast() {
    let mut addr: u32 = 0;
    let rc = unsafe { __inet_aton_exact(c"255.255.255.255".as_ptr(), &mut addr) };
    assert_eq!(rc, 1);
    assert_eq!(addr.to_ne_bytes(), [255, 255, 255, 255]);
}

#[test]
fn test_inet_aton_exact_invalid_empty() {
    let mut addr: u32 = 0;
    let rc = unsafe { __inet_aton_exact(c"".as_ptr(), &mut addr) };
    assert_eq!(rc, 0);
}

#[test]
fn test_inet_aton_exact_invalid_text() {
    let mut addr: u32 = 0;
    let rc = unsafe { __inet_aton_exact(c"not_an_ip".as_ptr(), &mut addr) };
    assert_eq!(rc, 0);
}

#[test]
fn test_inet_aton_exact_invalid_too_few_octets() {
    let mut addr: u32 = 0;
    let rc = unsafe { __inet_aton_exact(c"1.2.3".as_ptr(), &mut addr) };
    assert_eq!(rc, 0);
}

#[test]
fn test_inet_aton_exact_invalid_overflow() {
    let mut addr: u32 = 0;
    let rc = unsafe { __inet_aton_exact(c"256.0.0.1".as_ptr(), &mut addr) };
    assert_eq!(rc, 0);
}

#[test]
fn test_inet_aton_exact_null_input() {
    let mut addr: u32 = 0;
    let rc = unsafe { __inet_aton_exact(std::ptr::null(), &mut addr) };
    assert_eq!(rc, 0);
}

#[test]
fn inet_text_parsers_reject_tracked_unterminated_inputs() {
    unsafe {
        let raw_ip = malloc_unterminated(b"192.168.1.1");
        let mut addr: u32 = 0;
        assert_eq!(__inet_aton_exact(raw_ip, &mut addr), 0);
        assert_eq!(
            frankenlibc_abi::glibc_internal_abi::inet_network(raw_ip),
            u32::MAX
        );

        let mut net = [0u8; 4];
        *__errno_location() = 0;
        let prefix = frankenlibc_abi::glibc_internal_abi::inet_net_pton(
            libc::AF_INET,
            raw_ip,
            net.as_mut_ptr().cast(),
            net.len(),
        );
        let net_errno = *__errno_location();
        frankenlibc_abi::malloc_abi::free(raw_ip.cast());
        assert_eq!(prefix, -1);
        assert_eq!(net_errno, libc::EINVAL);

        let raw_nsap = malloc_unterminated(b"47000580ffff");
        let mut nsap = [0u8; 8];
        let parsed = frankenlibc_abi::glibc_internal_abi::inet_nsap_addr(
            raw_nsap,
            nsap.as_mut_ptr().cast(),
            nsap.len() as i32,
        );
        frankenlibc_abi::malloc_abi::free(raw_nsap.cast());
        assert_eq!(parsed, 0);
    }
}

#[test]
fn inet_nsap_helpers_cap_tracked_short_buffers() {
    unsafe {
        let text = CString::new("abcd").unwrap();
        let out = malloc_tracked_zeroed_bytes(1).cast::<u8>();
        let parsed =
            frankenlibc_abi::glibc_internal_abi::inet_nsap_addr(text.as_ptr(), out.cast(), 8);
        assert_eq!(parsed, 1);
        assert_eq!(*out, 0xab);
        frankenlibc_abi::malloc_abi::free(out.cast());

        let src = [0xab, 0xcd];
        let short_text = malloc_tracked_zeroed_bytes(4).cast::<c_char>();
        std::ptr::write_bytes(short_text.cast::<u8>(), 0x7e, 4);
        let returned = frankenlibc_abi::glibc_internal_abi::inet_nsap_ntoa(
            src.len() as c_int,
            src.as_ptr().cast(),
            short_text,
        );
        assert_eq!(returned, short_text);
        assert_eq!(*short_text, 0);
        assert_eq!(*short_text.add(1) as u8, 0x7e);
        frankenlibc_abi::malloc_abi::free(short_text.cast());

        let short_src = malloc_tracked_zeroed_bytes(1).cast::<u8>();
        *short_src = 0xab;
        let mut text_buf = [0x7eu8; 16];
        let returned = frankenlibc_abi::glibc_internal_abi::inet_nsap_ntoa(
            2,
            short_src.cast(),
            text_buf.as_mut_ptr().cast(),
        );
        assert_eq!(returned, text_buf.as_mut_ptr().cast::<c_char>());
        assert_eq!(text_buf[0], 0);
        assert_eq!(text_buf[1], 0x7e);
        frankenlibc_abi::malloc_abi::free(short_src.cast());
    }
}

// ===========================================================================
// __inet_pton_length — inet_pton with explicit source length
// ===========================================================================

#[test]
fn test_inet_pton_length_ipv4() {
    let src = b"10.0.0.1";
    let mut dst = [0u8; 4];
    let rc = unsafe {
        __inet_pton_length(
            2, // AF_INET
            src.as_ptr() as *const std::ffi::c_char,
            src.len(),
            dst.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    assert_eq!(rc, 1);
    assert_eq!(dst, [10, 0, 0, 1]);
}

#[test]
fn test_inet_pton_length_ipv6_loopback() {
    let src = b"::1";
    let mut dst = [0u8; 16];
    let rc = unsafe {
        __inet_pton_length(
            10, // AF_INET6
            src.as_ptr() as *const std::ffi::c_char,
            src.len(),
            dst.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    assert_eq!(rc, 1);
    assert_eq!(dst[15], 1);
    assert_eq!(dst[..15], [0u8; 15]);
}

#[test]
fn test_inet_pton_length_ipv4_with_extra_ignored() {
    // Pass only the first 7 bytes: "10.0.0." — should fail because incomplete
    let src = b"10.0.0.1GARBAGE";
    let mut dst = [0u8; 4];
    let rc = unsafe {
        __inet_pton_length(
            2,
            src.as_ptr() as *const std::ffi::c_char,
            8, // Only "10.0.0.1"
            dst.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    assert_eq!(rc, 1);
    assert_eq!(dst, [10, 0, 0, 1]);
}

#[test]
fn test_inet_pton_length_truncated_fails() {
    let src = b"10.0.0.1";
    let mut dst = [0u8; 4];
    let rc = unsafe {
        __inet_pton_length(
            2,
            src.as_ptr() as *const std::ffi::c_char,
            5, // Only "10.0." — incomplete
            dst.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    assert_eq!(rc, 0); // Invalid address
}

#[test]
fn test_inet_pton_length_unsupported_family() {
    let src = b"10.0.0.1";
    let mut dst = [0u8; 16];
    let rc = unsafe {
        __inet_pton_length(
            99, // Unsupported
            src.as_ptr() as *const std::ffi::c_char,
            src.len(),
            dst.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    assert_eq!(rc, -1);
}

#[test]
fn test_inet_pton_length_null_src() {
    let mut dst = [0u8; 4];
    let rc = unsafe {
        __inet_pton_length(
            2,
            std::ptr::null(),
            0,
            dst.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    assert_eq!(rc, -1);
}

#[test]
fn inet_pton_length_rejects_tracked_short_source() {
    unsafe {
        let src = malloc_tracked_zeroed_bytes(4).cast::<u8>();
        std::ptr::copy_nonoverlapping(b"10.0".as_ptr(), src, 4);
        let mut dst = [0xa5u8; 4];
        let rc = __inet_pton_length(2, src.cast(), 8, dst.as_mut_ptr().cast());
        assert_eq!(rc, -1);
        assert_eq!(dst, [0xa5; 4]);
        frankenlibc_abi::malloc_abi::free(src.cast());
    }
}

#[test]
fn inet_pton_length_rejects_tracked_short_destination() {
    unsafe {
        let src = b"10.0.0.1";
        let dst = malloc_tracked_zeroed_bytes(2).cast::<u8>();
        std::ptr::write_bytes(dst, 0xa5, 2);
        let rc = __inet_pton_length(2, src.as_ptr().cast(), src.len(), dst.cast());
        assert_eq!(rc, -1);
        assert_eq!(*dst, 0xa5);
        assert_eq!(*dst.add(1), 0xa5);
        frankenlibc_abi::malloc_abi::free(dst.cast());
    }
}

// ===========================================================================
// __inet6_scopeid_pton — parse IPv6 scope ID
// ===========================================================================

#[test]
fn test_inet6_scopeid_pton_numeric() {
    let scope = b"42";
    let addr = [0u8; 16]; // dummy addr
    let rc = unsafe {
        __inet6_scopeid_pton(
            addr.as_ptr() as *const std::ffi::c_void,
            scope.as_ptr() as *const std::ffi::c_char,
            scope.len(),
        )
    };
    assert_eq!(rc, 42);
}

#[test]
fn test_inet6_scopeid_pton_zero() {
    let scope = b"0";
    let addr = [0u8; 16];
    let rc = unsafe {
        __inet6_scopeid_pton(
            addr.as_ptr() as *const std::ffi::c_void,
            scope.as_ptr() as *const std::ffi::c_char,
            scope.len(),
        )
    };
    assert_eq!(rc, 0);
}

#[test]
fn test_inet6_scopeid_pton_large_numeric() {
    let scope = b"1000";
    let addr = [0u8; 16];
    let rc = unsafe {
        __inet6_scopeid_pton(
            addr.as_ptr() as *const std::ffi::c_void,
            scope.as_ptr() as *const std::ffi::c_char,
            scope.len(),
        )
    };
    assert_eq!(rc, 1000);
}

#[test]
fn test_inet6_scopeid_pton_empty_returns_enoent() {
    let addr = [0u8; 16];
    let rc = unsafe {
        __inet6_scopeid_pton(
            addr.as_ptr() as *const std::ffi::c_void,
            std::ptr::null(),
            0,
        )
    };
    assert_eq!(rc, libc::ENOENT);
}

#[test]
fn test_inet6_scopeid_pton_invalid_name() {
    // Non-numeric, non-existent interface name
    let scope = b"nonexistent_iface_xyz_12345";
    let addr = [0u8; 16];
    let rc = unsafe {
        __inet6_scopeid_pton(
            addr.as_ptr() as *const std::ffi::c_void,
            scope.as_ptr() as *const std::ffi::c_char,
            scope.len(),
        )
    };
    assert_eq!(rc, libc::ENOENT);
}

// ===========================================================================
// IDNA encoding/decoding tests (native Punycode, RFC 3492)
// ===========================================================================

#[test]
fn test_idna_to_dns_ascii_passthrough() {
    // Pure ASCII hostname should pass through unchanged.
    let name = std::ffi::CString::new("example.com").unwrap();
    let mut result: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe { __idna_to_dns_encoding(name.as_ptr(), &mut result) };
    assert_eq!(rc, 0);
    assert!(!result.is_null());
    let out = unsafe { std::ffi::CStr::from_ptr(result) }
        .to_str()
        .unwrap();
    assert_eq!(out, "example.com");
    unsafe { libc::free(result as *mut std::ffi::c_void) };
}

#[test]
fn test_idna_to_dns_unicode_label() {
    // "münchen.de" should encode to "xn--mnchen-3ya.de"
    let name = std::ffi::CString::new("münchen.de").unwrap();
    let mut result: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe { __idna_to_dns_encoding(name.as_ptr(), &mut result) };
    assert_eq!(rc, 0);
    assert!(!result.is_null());
    let out = unsafe { std::ffi::CStr::from_ptr(result) }
        .to_str()
        .unwrap();
    assert_eq!(out, "xn--mnchen-3ya.de");
    unsafe { libc::free(result as *mut std::ffi::c_void) };
}

#[test]
fn test_idna_to_dns_chinese() {
    // Chinese domain label.
    let name = std::ffi::CString::new("中文.com").unwrap();
    let mut result: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe { __idna_to_dns_encoding(name.as_ptr(), &mut result) };
    assert_eq!(rc, 0);
    assert!(!result.is_null());
    let out = unsafe { std::ffi::CStr::from_ptr(result) }
        .to_str()
        .unwrap();
    // "中文" in Punycode is "fiq228c".
    assert_eq!(out, "xn--fiq228c.com");
    unsafe { libc::free(result as *mut std::ffi::c_void) };
}

#[test]
fn test_idna_to_dns_null_input() {
    let mut result: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe { __idna_to_dns_encoding(std::ptr::null(), &mut result) };
    assert_eq!(rc, libc::EAI_FAIL);
}

#[test]
fn test_idna_to_dns_null_result_ptr() {
    let name = std::ffi::CString::new("test.com").unwrap();
    let rc = unsafe { __idna_to_dns_encoding(name.as_ptr(), std::ptr::null_mut()) };
    assert_eq!(rc, libc::EAI_FAIL);
}

#[test]
fn test_idna_rejects_tracked_unterminated_names() {
    let name = b"m\xc3\xbcnchen.de";

    unsafe {
        let raw = malloc_unterminated(name);
        let mut encoded: *mut std::ffi::c_char = std::ptr::null_mut();
        let encode_rc = __idna_to_dns_encoding(raw, &mut encoded);
        assert_eq!(encode_rc, libc::EAI_FAIL);
        assert!(encoded.is_null());

        let mut decoded: *mut std::ffi::c_char = std::ptr::null_mut();
        let decode_rc = __idna_from_dns_encoding(raw, &mut decoded);
        frankenlibc_abi::malloc_abi::free(raw.cast());

        assert_eq!(decode_rc, libc::EAI_FAIL);
        assert!(decoded.is_null());
    }
}

#[test]
fn test_idna_from_dns_ascii_passthrough() {
    // Pure ASCII hostname should pass through unchanged.
    let name = std::ffi::CString::new("example.com").unwrap();
    let mut result: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe { __idna_from_dns_encoding(name.as_ptr(), &mut result) };
    assert_eq!(rc, 0);
    assert!(!result.is_null());
    let out = unsafe { std::ffi::CStr::from_ptr(result) }
        .to_str()
        .unwrap();
    assert_eq!(out, "example.com");
    unsafe { libc::free(result as *mut std::ffi::c_void) };
}

#[test]
fn test_idna_from_dns_punycode_label() {
    // "xn--mnchen-3ya.de" should decode to "münchen.de"
    let name = std::ffi::CString::new("xn--mnchen-3ya.de").unwrap();
    let mut result: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe { __idna_from_dns_encoding(name.as_ptr(), &mut result) };
    assert_eq!(rc, 0);
    assert!(!result.is_null());
    let out = unsafe { std::ffi::CStr::from_ptr(result) }
        .to_str()
        .unwrap();
    assert_eq!(out, "münchen.de");
    unsafe { libc::free(result as *mut std::ffi::c_void) };
}

#[test]
fn test_idna_from_dns_chinese_punycode() {
    // "xn--fiq228c.com" should decode back to "中文.com"
    let name = std::ffi::CString::new("xn--fiq228c.com").unwrap();
    let mut result: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe { __idna_from_dns_encoding(name.as_ptr(), &mut result) };
    assert_eq!(rc, 0);
    assert!(!result.is_null());
    let out = unsafe { std::ffi::CStr::from_ptr(result) }
        .to_str()
        .unwrap();
    assert_eq!(out, "中文.com");
    unsafe { libc::free(result as *mut std::ffi::c_void) };
}

#[test]
fn test_idna_roundtrip_unicode() {
    // Encode then decode should produce original.
    let original = "münchen.de";
    let name = std::ffi::CString::new(original).unwrap();

    // Encode.
    let mut encoded: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe { __idna_to_dns_encoding(name.as_ptr(), &mut encoded) };
    assert_eq!(rc, 0);
    assert!(!encoded.is_null());

    // Decode.
    let mut decoded: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc2 = unsafe { __idna_from_dns_encoding(encoded, &mut decoded) };
    assert_eq!(rc2, 0);
    assert!(!decoded.is_null());

    let result = unsafe { std::ffi::CStr::from_ptr(decoded) }
        .to_str()
        .unwrap();
    assert_eq!(result, original);

    unsafe {
        libc::free(encoded as *mut std::ffi::c_void);
        libc::free(decoded as *mut std::ffi::c_void);
    }
}

#[test]
fn test_idna_from_dns_null_input() {
    let mut result: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe { __idna_from_dns_encoding(std::ptr::null(), &mut result) };
    assert_eq!(rc, libc::EAI_FAIL);
}

#[test]
fn test_idna_from_dns_case_insensitive_prefix() {
    // xn-- prefix matching should be case-insensitive.
    let name = std::ffi::CString::new("XN--mnchen-3ya.de").unwrap();
    let mut result: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe { __idna_from_dns_encoding(name.as_ptr(), &mut result) };
    assert_eq!(rc, 0);
    assert!(!result.is_null());
    let out = unsafe { std::ffi::CStr::from_ptr(result) }
        .to_str()
        .unwrap();
    assert_eq!(out, "münchen.de");
    unsafe { libc::free(result as *mut std::ffi::c_void) };
}

#[test]
fn test_idna_roundtrip_japanese() {
    // Japanese domain: "日本語.jp"
    let original = "日本語.jp";
    let name = std::ffi::CString::new(original).unwrap();

    let mut encoded: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc = unsafe { __idna_to_dns_encoding(name.as_ptr(), &mut encoded) };
    assert_eq!(rc, 0);
    assert!(!encoded.is_null());

    let ace = unsafe { std::ffi::CStr::from_ptr(encoded) }
        .to_str()
        .unwrap();
    assert!(ace.starts_with("xn--"), "expected xn-- prefix, got: {ace}");
    assert!(ace.ends_with(".jp"), "expected .jp suffix, got: {ace}");

    let mut decoded: *mut std::ffi::c_char = std::ptr::null_mut();
    let rc2 = unsafe { __idna_from_dns_encoding(encoded, &mut decoded) };
    assert_eq!(rc2, 0);
    let result = unsafe { std::ffi::CStr::from_ptr(decoded) }
        .to_str()
        .unwrap();
    assert_eq!(result, original);

    unsafe {
        libc::free(encoded as *mut std::ffi::c_void);
        libc::free(decoded as *mut std::ffi::c_void);
    }
}

// ===========================================================================
// __call_tls_dtors tests (native TLS destructor invocation)
// ===========================================================================

fn run_tls_dtor_test_thread(entry: extern "C" fn(*mut std::ffi::c_void) -> *mut std::ffi::c_void) {
    let mut thread = std::mem::MaybeUninit::<libc::pthread_t>::uninit();
    let create_rc = unsafe {
        libc::pthread_create(
            thread.as_mut_ptr(),
            std::ptr::null(),
            entry,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(create_rc, 0, "pthread_create should succeed");

    let mut retval = std::ptr::null_mut();
    let join_rc = unsafe { libc::pthread_join(thread.assume_init(), &mut retval) };
    assert_eq!(join_rc, 0, "pthread_join should succeed");
    assert!(retval.is_null(), "TLS dtor test thread should exit cleanly");
}

#[test]
fn test_call_tls_dtors_noop_when_empty() {
    extern "C" fn entry(_arg: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
        frankenlibc_abi::startup_abi::clear_tls_dtors_for_tests();
        unsafe { __call_tls_dtors() };
        std::ptr::null_mut()
    }

    run_tls_dtor_test_thread(entry);
}

#[test]
fn test_call_tls_dtors_invokes_registered() {
    use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

    static DTOR_COUNT: AtomicU32 = AtomicU32::new(0);
    static REGISTER_RC: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn test_dtor(_obj: *mut std::ffi::c_void) {
        DTOR_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn entry(_arg: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
        DTOR_COUNT.store(0, Ordering::SeqCst);
        REGISTER_RC.store(0, Ordering::SeqCst);
        frankenlibc_abi::startup_abi::clear_tls_dtors_for_tests();

        for _ in 0..3 {
            let rc = unsafe {
                frankenlibc_abi::startup_abi::register_tls_dtor_for_tests(
                    test_dtor,
                    std::ptr::null_mut(),
                )
            };
            if rc != 0 {
                REGISTER_RC.store(rc, Ordering::SeqCst);
                return std::ptr::dangling_mut::<std::ffi::c_void>();
            }
        }

        unsafe { __call_tls_dtors() };
        std::ptr::null_mut()
    }

    run_tls_dtor_test_thread(entry);
    assert_eq!(REGISTER_RC.load(Ordering::SeqCst), 0);
    assert_eq!(DTOR_COUNT.load(Ordering::SeqCst), 3);
}

#[test]
fn test_call_tls_dtors_lifo_order() {
    use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};

    static ORDER_INDEX: AtomicUsize = AtomicUsize::new(0);
    static ORDER_0: AtomicU64 = AtomicU64::new(0);
    static ORDER_1: AtomicU64 = AtomicU64::new(0);
    static ORDER_2: AtomicU64 = AtomicU64::new(0);
    static REGISTER_RC: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn order_dtor(obj: *mut std::ffi::c_void) {
        let val = obj as u64;
        match ORDER_INDEX.fetch_add(1, Ordering::SeqCst) {
            0 => ORDER_0.store(val, Ordering::SeqCst),
            1 => ORDER_1.store(val, Ordering::SeqCst),
            2 => ORDER_2.store(val, Ordering::SeqCst),
            _ => {}
        }
    }

    extern "C" fn entry(_arg: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
        ORDER_INDEX.store(0, Ordering::SeqCst);
        ORDER_0.store(0, Ordering::SeqCst);
        ORDER_1.store(0, Ordering::SeqCst);
        ORDER_2.store(0, Ordering::SeqCst);
        REGISTER_RC.store(0, Ordering::SeqCst);
        frankenlibc_abi::startup_abi::clear_tls_dtors_for_tests();

        for i in 1u64..=3 {
            let rc = unsafe {
                frankenlibc_abi::startup_abi::register_tls_dtor_for_tests(
                    order_dtor,
                    i as *mut std::ffi::c_void,
                )
            };
            if rc != 0 {
                REGISTER_RC.store(rc, Ordering::SeqCst);
                return std::ptr::dangling_mut::<std::ffi::c_void>();
            }
        }

        unsafe { __call_tls_dtors() };
        std::ptr::null_mut()
    }

    run_tls_dtor_test_thread(entry);
    assert_eq!(REGISTER_RC.load(Ordering::SeqCst), 0);
    assert_eq!(ORDER_INDEX.load(Ordering::SeqCst), 3);
    assert_eq!(ORDER_0.load(Ordering::SeqCst), 3);
    assert_eq!(ORDER_1.load(Ordering::SeqCst), 2);
    assert_eq!(ORDER_2.load(Ordering::SeqCst), 1);
}

#[test]
fn test_call_tls_dtors_drains_list() {
    use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

    static DTOR2_COUNT: AtomicU32 = AtomicU32::new(0);
    static REGISTER_RC: AtomicI32 = AtomicI32::new(0);
    static AFTER_FIRST_CALL: AtomicU32 = AtomicU32::new(0);
    static AFTER_SECOND_CALL: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn dtor2(_obj: *mut std::ffi::c_void) {
        DTOR2_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn entry(_arg: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
        DTOR2_COUNT.store(0, Ordering::SeqCst);
        REGISTER_RC.store(0, Ordering::SeqCst);
        AFTER_FIRST_CALL.store(0, Ordering::SeqCst);
        AFTER_SECOND_CALL.store(0, Ordering::SeqCst);
        frankenlibc_abi::startup_abi::clear_tls_dtors_for_tests();

        let rc = unsafe {
            frankenlibc_abi::startup_abi::register_tls_dtor_for_tests(dtor2, std::ptr::null_mut())
        };
        if rc != 0 {
            REGISTER_RC.store(rc, Ordering::SeqCst);
            return std::ptr::dangling_mut::<std::ffi::c_void>();
        }

        unsafe { __call_tls_dtors() };
        AFTER_FIRST_CALL.store(DTOR2_COUNT.load(Ordering::SeqCst), Ordering::SeqCst);

        unsafe { __call_tls_dtors() };
        AFTER_SECOND_CALL.store(DTOR2_COUNT.load(Ordering::SeqCst), Ordering::SeqCst);
        std::ptr::null_mut()
    }

    run_tls_dtor_test_thread(entry);
    assert_eq!(REGISTER_RC.load(Ordering::SeqCst), 0);
    assert_eq!(AFTER_FIRST_CALL.load(Ordering::SeqCst), 1);
    assert_eq!(AFTER_SECOND_CALL.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// __b64_ntop / __b64_pton (BIND/libresolv RFC 4648 base64)
// ---------------------------------------------------------------------------

use frankenlibc_abi::glibc_internal_abi::{__b64_ntop, __b64_pton, b64_ntop, b64_pton};

#[test]
fn b64_ntop_rfc4648_vector() {
    let src = b"foobar";
    let mut buf = [0u8; 16];
    let n = unsafe {
        b64_ntop(
            src.as_ptr(),
            src.len(),
            buf.as_mut_ptr() as *mut std::ffi::c_char,
            buf.len(),
        )
    };
    assert_eq!(n, 8);
    assert_eq!(&buf[..n as usize], b"Zm9vYmFy");
    assert_eq!(buf[n as usize], 0);
}

#[test]
fn b64_ntop_returns_minus_one_when_target_too_small() {
    let src = b"foobar";
    let mut buf = [0u8; 4];
    let n = unsafe {
        b64_ntop(
            src.as_ptr(),
            src.len(),
            buf.as_mut_ptr() as *mut std::ffi::c_char,
            buf.len(),
        )
    };
    assert_eq!(n, -1);
}

#[test]
fn b64_ntop_handles_empty_src() {
    let mut buf = [0xffu8; 4];
    let n = unsafe {
        b64_ntop(
            std::ptr::null(),
            0,
            buf.as_mut_ptr() as *mut std::ffi::c_char,
            buf.len(),
        )
    };
    assert_eq!(n, 0);
    assert_eq!(
        buf[0], 0,
        "empty src must produce empty NUL-terminated string"
    );
}

#[test]
fn b64_ntop_null_target_is_error() {
    let src = b"x";
    let n = unsafe { b64_ntop(src.as_ptr(), src.len(), std::ptr::null_mut(), 0) };
    assert_eq!(n, -1);
}

#[test]
fn b64_ntop_rejects_unrepresentable_target_size() {
    let src = b"x";
    let mut buf = [0u8; 1];
    let n = unsafe {
        b64_ntop(
            src.as_ptr(),
            src.len(),
            buf.as_mut_ptr() as *mut std::ffi::c_char,
            usize::MAX,
        )
    };
    assert_eq!(n, -1);
}

#[test]
fn b64_pton_rfc4648_vector() {
    let s = b"Zm9vYmFy\0";
    let mut buf = [0u8; 8];
    let n = unsafe {
        b64_pton(
            s.as_ptr() as *const std::ffi::c_char,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    assert_eq!(n, 6);
    assert_eq!(&buf[..n as usize], b"foobar");
}

#[test]
fn b64_pton_returns_minus_one_for_invalid_char() {
    let s = b"Zm9v!Zg==\0";
    let mut buf = [0u8; 8];
    let n = unsafe {
        b64_pton(
            s.as_ptr() as *const std::ffi::c_char,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    assert_eq!(n, -1);
}

#[test]
fn b64_pton_returns_minus_one_when_target_too_small() {
    let s = b"Zm9v\0";
    let mut buf = [0u8; 1];
    let n = unsafe {
        b64_pton(
            s.as_ptr() as *const std::ffi::c_char,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    assert_eq!(n, -1);
}

#[test]
fn b64_pton_rejects_unrepresentable_target_size() {
    let s = b"AA==\0";
    let mut buf = [0u8; 1];
    let n = unsafe {
        b64_pton(
            s.as_ptr() as *const std::ffi::c_char,
            buf.as_mut_ptr(),
            usize::MAX,
        )
    };
    assert_eq!(n, -1);
}

#[test]
fn b64_pton_null_src_is_error() {
    let mut buf = [0u8; 8];
    let n = unsafe { b64_pton(std::ptr::null(), buf.as_mut_ptr(), buf.len()) };
    assert_eq!(n, -1);
}

#[test]
fn b64_pton_null_target_reports_decoded_length() {
    let s = b"Zm9v\0";
    let n = unsafe {
        b64_pton(
            s.as_ptr() as *const std::ffi::c_char,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(n, 3);

    let alias_n = unsafe {
        __b64_pton(
            s.as_ptr() as *const std::ffi::c_char,
            std::ptr::null_mut(),
            128,
        )
    };
    assert_eq!(alias_n, 3);

    let ignored_size_n = unsafe {
        b64_pton(
            s.as_ptr() as *const std::ffi::c_char,
            std::ptr::null_mut(),
            usize::MAX,
        )
    };
    assert_eq!(ignored_size_n, 3);
}

#[test]
fn b64_pton_skips_whitespace_for_wrapped_input() {
    let s = b"Zm9v\nYmFy\n\0";
    let mut buf = [0u8; 8];
    let n = unsafe {
        b64_pton(
            s.as_ptr() as *const std::ffi::c_char,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    assert_eq!(n, 6);
    assert_eq!(&buf[..n as usize], b"foobar");
}

#[test]
fn underscore_b64_ntop_alias_matches_b64_ntop() {
    let src = b"hi";
    let mut buf1 = [0u8; 8];
    let mut buf2 = [0u8; 8];
    let n1 = unsafe {
        b64_ntop(
            src.as_ptr(),
            src.len(),
            buf1.as_mut_ptr() as *mut std::ffi::c_char,
            buf1.len(),
        )
    };
    let n2 = unsafe {
        __b64_ntop(
            src.as_ptr(),
            src.len(),
            buf2.as_mut_ptr() as *mut std::ffi::c_char,
            buf2.len(),
        )
    };
    assert_eq!(n1, n2);
    assert_eq!(buf1, buf2);
}

#[test]
fn underscore_b64_pton_alias_matches_b64_pton() {
    let s = b"aGk=\0";
    let mut buf1 = [0u8; 4];
    let mut buf2 = [0u8; 4];
    let n1 = unsafe {
        b64_pton(
            s.as_ptr() as *const std::ffi::c_char,
            buf1.as_mut_ptr(),
            buf1.len(),
        )
    };
    let n2 = unsafe {
        __b64_pton(
            s.as_ptr() as *const std::ffi::c_char,
            buf2.as_mut_ptr(),
            buf2.len(),
        )
    };
    assert_eq!(n1, n2);
    assert_eq!(buf1, buf2);
}

#[test]
fn b64_round_trip_arbitrary_bytes() {
    let input: Vec<u8> = (0u8..=200).collect();
    let mut enc = vec![0u8; (input.len().div_ceil(3)) * 4 + 1];
    let enc_n = unsafe {
        b64_ntop(
            input.as_ptr(),
            input.len(),
            enc.as_mut_ptr() as *mut std::ffi::c_char,
            enc.len(),
        )
    };
    assert!(enc_n > 0);

    let mut dec = vec![0u8; input.len()];
    let dec_n = unsafe {
        b64_pton(
            enc.as_ptr() as *const std::ffi::c_char,
            dec.as_mut_ptr(),
            dec.len(),
        )
    };
    assert_eq!(dec_n as usize, input.len());
    assert_eq!(dec, input);
}

// ---------------------------------------------------------------------------
// inet_net_pton / inet_net_ntop (BIND/libresolv CIDR codec)
// ---------------------------------------------------------------------------

use frankenlibc_abi::glibc_internal_abi::{inet_net_ntop, inet_net_pton};

#[test]
fn inet_net_pton_full_dotted_quad() {
    let s = c"192.168.0.1";
    let mut dst = [0u8; 4];
    let p = unsafe {
        inet_net_pton(
            libc::AF_INET,
            s.as_ptr(),
            dst.as_mut_ptr() as *mut std::ffi::c_void,
            dst.len(),
        )
    };
    assert_eq!(p, 32);
    assert_eq!(dst, [192, 168, 0, 1]);
}

#[test]
fn inet_net_pton_implicit_prefix() {
    let s = c"10";
    let mut dst = [0u8; 4];
    let p = unsafe {
        inet_net_pton(
            libc::AF_INET,
            s.as_ptr(),
            dst.as_mut_ptr() as *mut std::ffi::c_void,
            dst.len(),
        )
    };
    assert_eq!(p, 8);
    assert_eq!(dst[0], 10);
}

#[test]
fn inet_net_pton_explicit_prefix() {
    let s = c"192.168.0/24";
    let mut dst = [0u8; 4];
    let p = unsafe {
        inet_net_pton(
            libc::AF_INET,
            s.as_ptr(),
            dst.as_mut_ptr() as *mut std::ffi::c_void,
            dst.len(),
        )
    };
    assert_eq!(p, 24);
    assert_eq!(&dst[..3], &[192, 168, 0]);
}

#[test]
fn inet_net_pton_invalid_returns_minus_one_with_einval() {
    let s = c"256.0.0.1";
    let mut dst = [0u8; 4];
    unsafe { *__errno_location() = 0 };
    let p = unsafe {
        inet_net_pton(
            libc::AF_INET,
            s.as_ptr(),
            dst.as_mut_ptr() as *mut std::ffi::c_void,
            dst.len(),
        )
    };
    assert_eq!(p, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EINVAL);
}

#[test]
fn inet_net_pton_buffer_too_small_sets_emsgsize() {
    let s = c"192.168.0.1";
    let mut dst = [0u8; 1];
    unsafe { *__errno_location() = 0 };
    let p = unsafe {
        inet_net_pton(
            libc::AF_INET,
            s.as_ptr(),
            dst.as_mut_ptr() as *mut std::ffi::c_void,
            dst.len(),
        )
    };
    assert_eq!(p, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EMSGSIZE);
}

#[test]
fn inet_net_pton_caps_tracked_short_output_buffer() {
    let s = c"192.168.0.1";
    unsafe {
        let raw = malloc_tracked_zeroed_bytes(1);
        clear_errno();
        let p = inet_net_pton(libc::AF_INET, s.as_ptr(), raw, 4);
        assert_eq!(p, -1);
        assert_eq!(errno_value(), libc::EMSGSIZE);
        assert_eq!(raw.cast::<u8>().read(), 0);
        frankenlibc_abi::malloc_abi::free(raw);
    }
}

#[test]
fn inet_net_pton_unknown_af_sets_eafnosupport() {
    let s = c"192.168.0/24";
    let mut dst = [0u8; 4];
    unsafe { *__errno_location() = 0 };
    let p = unsafe {
        inet_net_pton(
            libc::AF_INET6,
            s.as_ptr(),
            dst.as_mut_ptr() as *mut std::ffi::c_void,
            dst.len(),
        )
    };
    assert_eq!(p, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EAFNOSUPPORT);
}

#[test]
fn inet_net_pton_null_src_returns_einval() {
    let mut dst = [0u8; 4];
    unsafe { *__errno_location() = 0 };
    let p = unsafe {
        inet_net_pton(
            libc::AF_INET,
            std::ptr::null(),
            dst.as_mut_ptr() as *mut std::ffi::c_void,
            dst.len(),
        )
    };
    assert_eq!(p, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EINVAL);
}

#[test]
fn inet_net_ntop_renders_24_bit_network() {
    let bytes = [192u8, 168, 0];
    let mut dst = [0u8; 32];
    let p = unsafe {
        inet_net_ntop(
            libc::AF_INET,
            bytes.as_ptr() as *const std::ffi::c_void,
            24,
            dst.as_mut_ptr() as *mut std::ffi::c_char,
            dst.len(),
        )
    };
    assert!(!p.is_null());
    let s = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes();
    assert_eq!(s, b"192.168.0/24");
}

#[test]
fn inet_net_ntop_renders_full_host() {
    let bytes = [192u8, 168, 0, 1];
    let mut dst = [0u8; 32];
    let p = unsafe {
        inet_net_ntop(
            libc::AF_INET,
            bytes.as_ptr() as *const std::ffi::c_void,
            32,
            dst.as_mut_ptr() as *mut std::ffi::c_char,
            dst.len(),
        )
    };
    assert!(!p.is_null());
    let s = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes();
    assert_eq!(s, b"192.168.0.1/32");
}

#[test]
fn inet_net_ntop_caps_tracked_short_output_buffer() {
    let bytes = [192u8, 168, 0, 1];
    unsafe {
        let raw = malloc_tracked_zeroed_bytes(4);
        clear_errno();
        let p = inet_net_ntop(libc::AF_INET, bytes.as_ptr().cast(), 32, raw.cast(), 32);
        assert!(p.is_null());
        assert_eq!(errno_value(), libc::EMSGSIZE);
        assert_eq!(raw.cast::<u8>().read(), 0);
        frankenlibc_abi::malloc_abi::free(raw);
    }
}

#[test]
fn inet_net_ntop_buffer_too_small_returns_null_with_emsgsize() {
    let bytes = [192u8, 168, 0, 1];
    let mut dst = [0u8; 4]; // can't fit "192.168.0.1\0"
    unsafe { *__errno_location() = 0 };
    let p = unsafe {
        inet_net_ntop(
            libc::AF_INET,
            bytes.as_ptr() as *const std::ffi::c_void,
            32,
            dst.as_mut_ptr() as *mut std::ffi::c_char,
            dst.len(),
        )
    };
    assert!(p.is_null());
    assert_eq!(unsafe { *__errno_location() }, libc::EMSGSIZE);
}

#[test]
fn inet_net_ntop_unknown_af_returns_null_with_eafnosupport() {
    let bytes = [192u8, 168, 0, 1];
    let mut dst = [0u8; 32];
    unsafe { *__errno_location() = 0 };
    let p = unsafe {
        inet_net_ntop(
            libc::AF_INET6,
            bytes.as_ptr() as *const std::ffi::c_void,
            32,
            dst.as_mut_ptr() as *mut std::ffi::c_char,
            dst.len(),
        )
    };
    assert!(p.is_null());
    assert_eq!(unsafe { *__errno_location() }, libc::EAFNOSUPPORT);
}

#[test]
fn inet_net_round_trip_via_abi() {
    // pton "10.1/16" → bytes [10,1] + prefix 16 → ntop → "10.1/16".
    let s = c"10.1/16";
    let mut bytes = [0u8; 4];
    let p = unsafe {
        inet_net_pton(
            libc::AF_INET,
            s.as_ptr(),
            bytes.as_mut_ptr() as *mut std::ffi::c_void,
            bytes.len(),
        )
    };
    assert_eq!(p, 16);

    let mut dst = [0u8; 32];
    let out = unsafe {
        inet_net_ntop(
            libc::AF_INET,
            bytes.as_ptr() as *const std::ffi::c_void,
            p,
            dst.as_mut_ptr() as *mut std::ffi::c_char,
            dst.len(),
        )
    };
    assert!(!out.is_null());
    let result = unsafe { std::ffi::CStr::from_ptr(out) }.to_bytes();
    assert_eq!(result, b"10.1/16");
}

// ---------------------------------------------------------------------------
// __libc_alloca_cutoff / __libc_use_alloca
// ---------------------------------------------------------------------------

use frankenlibc_abi::glibc_internal_abi::{__libc_alloca_cutoff, __libc_use_alloca};

#[test]
fn libc_alloca_cutoff_returns_one_for_small_sizes() {
    assert_eq!(unsafe { __libc_alloca_cutoff(0) }, 1);
    assert_eq!(unsafe { __libc_alloca_cutoff(1) }, 1);
    assert_eq!(unsafe { __libc_alloca_cutoff(64) }, 1);
    assert_eq!(unsafe { __libc_alloca_cutoff(1024) }, 1);
}

#[test]
fn libc_alloca_cutoff_returns_zero_for_huge_sizes() {
    // Sizes well above any plausible threshold (1 MiB, 1 GiB, SIZE_MAX).
    assert_eq!(unsafe { __libc_alloca_cutoff(1 << 20) }, 0);
    assert_eq!(unsafe { __libc_alloca_cutoff(1 << 30) }, 0);
    assert_eq!(unsafe { __libc_alloca_cutoff(usize::MAX) }, 0);
}

#[test]
fn libc_use_alloca_matches_libc_alloca_cutoff() {
    for size in [
        0usize,
        1,
        64,
        4096,
        16384,
        65536,
        1 << 20,
        1 << 30,
        usize::MAX,
    ] {
        assert_eq!(
            unsafe { __libc_use_alloca(size) },
            unsafe { __libc_alloca_cutoff(size) },
            "divergence at size {size}",
        );
    }
}

// ---------------------------------------------------------------------------
// __libc_fatal (glibc internal noreturn fatal-error helper)
// ---------------------------------------------------------------------------

use frankenlibc_abi::glibc_internal_abi::__libc_fatal;

#[test]
fn libc_fatal_aborts_child_with_message() {
    // The function never returns and aborts the process. Run it
    // in a forked child so we can observe SIGABRT without
    // killing the test runner.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let msg = c"frankenlibc test fatal\n";
        unsafe { __libc_fatal(msg.as_ptr()) };
    }
    let mut status: c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

#[test]
fn libc_fatal_null_message_still_aborts_with_fallback() {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        unsafe { __libc_fatal(std::ptr::null()) };
    }
    let mut status: c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

#[test]
fn libc_fatal_unterminated_message_still_aborts_with_fallback() {
    let raw_message = unsafe { malloc_unterminated(b"unterminated fatal message") };
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        unsafe { __libc_fatal(raw_message) };
    }
    let mut status: c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    unsafe {
        frankenlibc_abi::malloc_abi::free(raw_message.cast());
    }
    assert_eq!(waited, pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
}

// ---------------------------------------------------------------------------
// __libc_csu_init / __libc_csu_fini (glibc startup stub no-ops)
// ---------------------------------------------------------------------------

use frankenlibc_abi::glibc_internal_abi::{__libc_csu_fini, __libc_csu_init};

#[test]
fn libc_csu_init_is_a_no_op() {
    // Just verify the symbol resolves and the call returns.
    unsafe { __libc_csu_init(0, std::ptr::null_mut(), std::ptr::null_mut()) };
}

#[test]
fn libc_csu_init_with_argv_envp_is_a_no_op() {
    let arg0 = std::ffi::CString::new("test").unwrap();
    let mut argv: [*mut std::ffi::c_char; 2] = [arg0.as_ptr() as *mut _, std::ptr::null_mut()];
    let mut envp: [*mut std::ffi::c_char; 1] = [std::ptr::null_mut()];
    unsafe { __libc_csu_init(1, argv.as_mut_ptr(), envp.as_mut_ptr()) };
}

#[test]
fn libc_csu_fini_is_a_no_op() {
    unsafe { __libc_csu_fini() };
}

// ---------------------------------------------------------------------------
// __nss_lookup_function / __nss_hosts_lookup2 / __nss_next2
// ---------------------------------------------------------------------------

use frankenlibc_abi::glibc_internal_abi::{
    __nss_hosts_lookup2, __nss_lookup_function, __nss_next2,
};

#[test]
fn nss_lookup_function_returns_null() {
    let name = std::ffi::CString::new("getpwnam_r").unwrap();
    let p = unsafe { __nss_lookup_function(std::ptr::null_mut(), name.as_ptr()) };
    assert!(p.is_null());
}

#[test]
fn nss_hosts_lookup2_returns_unavail() {
    let name = std::ffi::CString::new("localhost").unwrap();
    let mut nip: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut errnop: c_int = 0;
    let mut h_errnop: c_int = 0;
    let rc = unsafe {
        __nss_hosts_lookup2(
            &mut nip,
            name.as_ptr(),
            libc::AF_INET,
            std::ptr::null_mut(),
            &mut errnop,
            &mut h_errnop,
        )
    };
    assert_eq!(rc, -1);
}

#[test]
fn nss_next2_returns_unavail() {
    let fct = std::ffi::CString::new("getpwnam_r").unwrap();
    let fct2 = std::ffi::CString::new("_nss_compat_getpwnam_r").unwrap();
    let mut ni: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut fctp: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut status: c_int = 0;
    let rc = unsafe {
        __nss_next2(
            &mut ni,
            fct.as_ptr(),
            fct2.as_ptr(),
            &mut fctp,
            &mut status,
            0,
        )
    };
    assert_eq!(rc, -1);
}

// ---------------------------------------------------------------------------
// Tests for 4 GLIBC_PRIVATE last-mile internal symbols (bd-kapb7)
// ---------------------------------------------------------------------------

#[test]
fn libc_dlerror_result_default_is_null() {
    use frankenlibc_abi::glibc_internal_abi::__libc_dlerror_result;
    let p = unsafe { (&raw const __libc_dlerror_result).read() };
    assert!(p.is_null());
}

#[test]
fn itoa_lower_digits_table_is_lowercase_hex() {
    use frankenlibc_abi::glibc_internal_abi::_itoa_lower_digits;
    let bytes: &[std::ffi::c_char; 17] = &_itoa_lower_digits;
    let s: Vec<u8> = bytes[..16].iter().map(|c| *c as u8).collect();
    assert_eq!(&s, b"0123456789abcdef");
    assert_eq!(bytes[16], 0);
}

#[test]
fn libc_fcntl64_forwards_to_fcntl_getfd() {
    use frankenlibc_abi::glibc_internal_abi::__libc_fcntl64;
    let f = std::fs::File::open("/dev/null").unwrap();
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&f);
    let flags = unsafe { __libc_fcntl64(fd, libc::F_GETFD, 0) };
    assert!(flags >= 0);
}

#[test]
fn libc_fcntl64_setfd_roundtrip() {
    use frankenlibc_abi::glibc_internal_abi::__libc_fcntl64;
    let f = std::fs::File::open("/dev/null").unwrap();
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&f);
    let original = unsafe { __libc_fcntl64(fd, libc::F_GETFD, 0) };
    assert!(original >= 0);
    let target = original | libc::FD_CLOEXEC;
    let rc = unsafe { __libc_fcntl64(fd, libc::F_SETFD, target as std::ffi::c_long) };
    assert_eq!(rc, 0);
    let after = unsafe { __libc_fcntl64(fd, libc::F_GETFD, 0) };
    assert_eq!(after & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
}

#[test]
fn libc_fcntl64_invalid_fd_returns_minus_one() {
    use frankenlibc_abi::glibc_internal_abi::__libc_fcntl64;
    let rc = unsafe { __libc_fcntl64(-1, libc::F_GETFD, 0) };
    assert_eq!(rc, -1);
}

#[test]
fn libc_mallinfo_reports_nonzero_arena_or_uordblks() {
    use frankenlibc_abi::glibc_internal_abi::__libc_mallinfo;
    // Ensure the allocator has been touched.
    let bumper: Vec<u8> = vec![0u8; 65536];
    std::hint::black_box(&bumper);
    let info = unsafe { __libc_mallinfo() };
    assert!(info.arena > 0 || info.uordblks > 0);
}

// ---------------------------------------------------------------------------
// Tests for 3 _Float128 libm classification helpers (bd-sy6p6)
// ---------------------------------------------------------------------------

#[test]
fn fpclassifyf128_classifies_nan_inf_zero_normal() {
    use frankenlibc_abi::glibc_internal_abi::__fpclassifyf128;
    // FP_NAN = 0, FP_INFINITE = 1, FP_ZERO = 2, FP_SUBNORMAL = 3, FP_NORMAL = 4
    assert_eq!(unsafe { __fpclassifyf128(f64::NAN) }, 0);
    assert_eq!(unsafe { __fpclassifyf128(f64::INFINITY) }, 1);
    assert_eq!(unsafe { __fpclassifyf128(0.0_f64) }, 2);
    assert_eq!(unsafe { __fpclassifyf128(1.0_f64) }, 4);
}

#[test]
fn isinff128_returns_signed_one_for_inf_zero_otherwise() {
    use frankenlibc_abi::glibc_internal_abi::__isinff128;
    assert_eq!(unsafe { __isinff128(f64::INFINITY) }, 1);
    assert_eq!(unsafe { __isinff128(f64::NEG_INFINITY) }, -1);
    assert_eq!(unsafe { __isinff128(0.0_f64) }, 0);
    assert_eq!(unsafe { __isinff128(1.0_f64) }, 0);
    assert_eq!(unsafe { __isinff128(f64::NAN) }, 0);
}

#[test]
fn signbitf128_distinguishes_positive_and_negative_zero() {
    use frankenlibc_abi::glibc_internal_abi::__signbitf128;
    assert_eq!(unsafe { __signbitf128(1.0_f64) }, 0);
    assert_eq!(unsafe { __signbitf128(-1.0_f64) }, 1);
    assert_eq!(unsafe { __signbitf128(0.0_f64) }, 0);
    assert_eq!(unsafe { __signbitf128(-0.0_f64) }, 1);
}

// ---------------------------------------------------------------------------
// Tests for 50 GLIBC_PRIVATE _thread_db_* libthread_db.so.1 introspection
// constants (bd-qn6q1)
// ---------------------------------------------------------------------------

#[test]
fn thread_db_offset_constants_are_zero_placeholders() {
    use frankenlibc_abi::glibc_internal_abi::*;
    // Sample-check that the offset/sizeof constants ship as zeroed
    // placeholders so libthread_db sees "no thread layout exposed".
    assert_eq!(_thread_db_const_thread_area, 0);
    assert_eq!(_thread_db_sizeof_pthread, 0);
    assert_eq!(_thread_db_sizeof_dtv_slotinfo, 0);
    assert_eq!(_thread_db_sizeof_pthread_key_data, 0);
    assert_eq!(_thread_db_sizeof_pthread_key_struct, 0);
    assert_eq!(_thread_db_pthread_tid, 0);
    assert_eq!(_thread_db_pthread_specific, 0);
    assert_eq!(_thread_db_pthread_list, 0);
    assert_eq!(_thread_db_link_map_l_tls_modid, 0);
    assert_eq!(_thread_db_link_map_l_tls_offset, 0);
    assert_eq!(_thread_db_dtv_dtv, 0);
    assert_eq!(_thread_db_dtv_t_pointer_val, 0);
    assert_eq!(_thread_db_td_eventbuf_t_eventnum, 0);
    assert_eq!(_thread_db_td_thr_events_t_event_bits, 0);
}

#[test]
fn thread_db_nptl_aliases_are_zero_placeholders() {
    use frankenlibc_abi::glibc_internal_abi::*;
    assert_eq!(_thread_db___nptl_last_event, 0);
    assert_eq!(_thread_db___nptl_nthreads, 0);
    assert_eq!(_thread_db___nptl_rtld_global, 0);
    assert_eq!(_thread_db___pthread_keys, 0);
}

#[test]
fn thread_db_key_struct_constants_are_zero_placeholders() {
    use frankenlibc_abi::glibc_internal_abi::*;
    assert_eq!(_thread_db_pthread_key_data_data, 0);
    assert_eq!(_thread_db_pthread_key_data_level2_data, 0);
    assert_eq!(_thread_db_pthread_key_data_seq, 0);
    assert_eq!(_thread_db_pthread_key_struct_destr, 0);
    assert_eq!(_thread_db_pthread_key_struct_seq, 0);
    assert_eq!(_thread_db_sizeof_pthread_key_data_level2, 0);
}

#[test]
fn thread_db_eventbuf_constants_are_zero_placeholders() {
    use frankenlibc_abi::glibc_internal_abi::*;
    assert_eq!(_thread_db_pthread_eventbuf, 0);
    assert_eq!(_thread_db_pthread_eventbuf_eventmask, 0);
    assert_eq!(_thread_db_pthread_eventbuf_eventmask_event_bits, 0);
    assert_eq!(_thread_db_sizeof_td_eventbuf_t, 0);
    assert_eq!(_thread_db_td_eventbuf_t_eventdata, 0);
    assert_eq!(_thread_db_pthread_nextevent, 0);
    assert_eq!(_thread_db_pthread_report_events, 0);
    assert_eq!(_thread_db_sizeof_td_thr_events_t, 0);
}

#[test]
fn thread_db_pthread_misc_constants_are_zero_placeholders() {
    use frankenlibc_abi::glibc_internal_abi::*;
    assert_eq!(_thread_db_pthread_cancelhandling, 0);
    assert_eq!(_thread_db_pthread_dtvp, 0);
    assert_eq!(_thread_db_pthread_schedparam_sched_priority, 0);
    assert_eq!(_thread_db_pthread_schedpolicy, 0);
    assert_eq!(_thread_db_pthread_start_routine, 0);
}

#[test]
fn thread_db_dtv_and_list_constants_are_zero_placeholders() {
    use frankenlibc_abi::glibc_internal_abi::*;
    assert_eq!(_thread_db_dtv_slotinfo_gen, 0);
    assert_eq!(_thread_db_dtv_slotinfo_list_len, 0);
    assert_eq!(_thread_db_dtv_slotinfo_list_next, 0);
    assert_eq!(_thread_db_dtv_slotinfo_list_slotinfo, 0);
    assert_eq!(_thread_db_dtv_slotinfo_map, 0);
    assert_eq!(_thread_db_dtv_t_counter, 0);
    assert_eq!(_thread_db_sizeof_dtv_slotinfo_list, 0);
    assert_eq!(_thread_db_list_t_next, 0);
    assert_eq!(_thread_db_list_t_prev, 0);
    assert_eq!(_thread_db_sizeof_list_t, 0);
}

#[test]
fn thread_db_rtld_global_constants_are_zero_placeholders() {
    use frankenlibc_abi::glibc_internal_abi::*;
    assert_eq!(_thread_db_rtld_global__dl_stack_used, 0);
    assert_eq!(_thread_db_rtld_global__dl_stack_user, 0);
    assert_eq!(_thread_db_rtld_global__dl_tls_dtv_slotinfo_list, 0);
}
