#![cfg(target_os = "linux")]

//! Integration tests for glibc_internal_abi entrypoints.

use frankenlibc_abi::glibc_internal_abi::{
    __asprintf,
    __nss_configure_lookup,
    __nss_database_lookup,
    __nss_group_lookup,
    __nss_hostname_digits_dots,
    __nss_hosts_lookup,
    __nss_next,
    __nss_passwd_lookup,
    __overflow,
    __printf_fp,
    // Session 13 additions:
    __res_mkquery,
    __res_send,
    __res_state,
    __strtof128_internal,
    __uflow,
    __underflow,
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
    xprt_register,
    xprt_unregister,
};
use std::ffi::CString;
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
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);
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
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);
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
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);
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
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);
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
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);

    let r = unsafe { __uflow(ptr::null_mut()) };
    assert_eq!(r, libc::EOF);
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);

    let r = unsafe { __underflow(ptr::null_mut()) };
    assert_eq!(r, libc::EOF);
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);
}

#[test]
fn wide_overflow_family_returns_wide_eof() {
    let r = unsafe { __woverflow(ptr::null_mut(), 'A' as i32) };
    assert_eq!(r, -1);
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);

    let r = unsafe { __wuflow(ptr::null_mut()) };
    assert_eq!(r, -1);
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);

    let r = unsafe { __wunderflow(ptr::null_mut()) };
    assert_eq!(r, -1);
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);
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
