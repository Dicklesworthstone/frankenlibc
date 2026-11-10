#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc getnameinfo oracle (libc, linked by std)

//! Randomized live differential fuzzer for `getnameinfo` (numeric mode) vs host
//! glibc. With NI_NUMERICHOST|NI_NUMERICSERV the call is fully deterministic (no
//! DNS, no /etc/services), so fl and glibc must produce byte-identical host and
//! service strings and the same return code. This sweeps random IPv4 and IPv6
//! sockaddrs — including IPv6 scope ids and IPv4-mapped / zero-run addresses,
//! exactly where address-to-text formatting (and the `%scope` suffix) diverge.

use std::ffi::{CStr, c_char, c_int};
use std::mem::size_of;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

use frankenlibc_abi::resolv_abi::getnameinfo as fl_getnameinfo;

fn host_getnameinfo() -> NameInfoFn {
    // SAFETY: NameInfoFn is exactly getnameinfo's C ABI. The shared resolver
    // opens host libc explicitly and rejects FrankenLibC's own definition.
    unsafe { dlsym_oracle::host_fn(c"getnameinfo", fl_getnameinfo as *const ()) }
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }
}

#[derive(PartialEq, Eq, Debug)]
struct Out {
    ret: c_int,
    host: String,
    serv: String,
}

unsafe fn call(
    f: unsafe extern "C" fn(
        *const libc::sockaddr,
        libc::socklen_t,
        *mut c_char,
        libc::socklen_t,
        *mut c_char,
        libc::socklen_t,
        c_int,
    ) -> c_int,
    sa: *const libc::sockaddr,
    salen: libc::socklen_t,
    flags: c_int,
) -> Out {
    let mut hbuf = [0u8; 1025]; // NI_MAXHOST
    let mut sbuf = [0u8; 32]; // NI_MAXSERV
    let ret = unsafe {
        f(
            sa,
            salen,
            hbuf.as_mut_ptr() as *mut c_char,
            hbuf.len() as libc::socklen_t,
            sbuf.as_mut_ptr() as *mut c_char,
            sbuf.len() as libc::socklen_t,
            flags,
        )
    };
    let host = if ret == 0 {
        unsafe { CStr::from_ptr(hbuf.as_ptr() as *const c_char) }
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };
    let serv = if ret == 0 {
        unsafe { CStr::from_ptr(sbuf.as_ptr() as *const c_char) }
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };
    Out { ret, host, serv }
}

#[test]
fn getnameinfo_numeric_differential_fuzz_vs_glibc() {
    let getnameinfo = host_getnameinfo();
    let mut r = Lcg(0x1234_dead_beef_5678);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;
    let flags = libc::NI_NUMERICHOST | libc::NI_NUMERICSERV;

    for _ in 0..60_000 {
        if r.next() & 1 == 0 {
            // ---- IPv4 ----
            let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            let octets = [r.byte(), r.byte(), r.byte(), r.byte()];
            sin.sin_addr.s_addr = u32::from_ne_bytes(octets);
            sin.sin_port = u16::from_ne_bytes([r.byte(), r.byte()]);
            let sa = &sin as *const _ as *const libc::sockaddr;
            let salen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let fl = unsafe { call(fl_getnameinfo, sa, salen, flags) };
            let host = unsafe { call(getnameinfo, sa, salen, flags) };
            compared += 1;
            if fl != host && divs.len() < 40 {
                divs.push(format!(
                    "AF_INET octets={octets:?} port_ne={:?}\n    fl   ={fl:?}\n    glibc={host:?}",
                    sin.sin_port
                ));
            }
        } else {
            // ---- IPv6 (random addr, port, scope id; bias toward zero runs) ----
            let mut a6 = [0u8; 16];
            for b in a6.iter_mut() {
                *b = r.byte();
            }
            if r.next() % 100 < 60 {
                let start = (r.next() as usize) % 16;
                let len = 1 + (r.next() as usize) % (16 - start);
                for b in &mut a6[start..start + len] {
                    *b = 0;
                }
            }
            // Occasionally force an IPv4-mapped prefix ::ffff:a.b.c.d.
            if r.next().is_multiple_of(5) {
                a6[..10].fill(0);
                a6[10] = 0xff;
                a6[11] = 0xff;
            }
            // Occasionally force a link-local (fe80::/10) or mc-link-local
            // (ff02::) prefix so the scope→interface-name path is exercised.
            match r.next() % 6 {
                0 => {
                    a6[0] = 0xfe;
                    a6[1] = 0x80;
                }
                1 => {
                    a6[0] = 0xff;
                    a6[1] = 0x02;
                }
                _ => {}
            }
            let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_addr.s6_addr = a6;
            sin6.sin6_port = u16::from_ne_bytes([r.byte(), r.byte()]);
            // Scope id: often 0, sometimes a small interface index.
            // Scope id: often 0, sometimes a small interface index (1 is
            // usually "lo", exercising the if_indextoname name path).
            sin6.sin6_scope_id = if r.next().is_multiple_of(3) {
                (r.next() % 5) as u32
            } else {
                0
            };
            let sa = &sin6 as *const _ as *const libc::sockaddr;
            let salen = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let fl = unsafe { call(fl_getnameinfo, sa, salen, flags) };
            let host = unsafe { call(getnameinfo, sa, salen, flags) };
            compared += 1;
            if fl != host && divs.len() < 40 {
                divs.push(format!(
                    "AF_INET6 addr={a6:02x?} scope={}\n    fl   ={fl:?}\n    glibc={host:?}",
                    sin6.sin6_scope_id
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "getnameinfo diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!(
        "getnameinfo numeric differential fuzz: {compared} comparisons, 0 divergences vs host glibc"
    );
}


type NameInfoFn = unsafe extern "C" fn(
    *const libc::sockaddr,
    libc::socklen_t,
    *mut c_char,
    libc::socklen_t,
    *mut c_char,
    libc::socklen_t,
    c_int,
) -> c_int;

#[derive(Debug, PartialEq, Eq)]
struct LocalOut {
    ret: c_int,
    errno: c_int,
    host: [u8; 256],
    serv: [u8; 256],
}

/// Compare complete buffers, including unchanged sentinels after the output
/// and on failure. Output pointers and lengths are independent: NULL with a
/// nonzero length and non-NULL with a zero length both omit an output.
unsafe fn call_local(
    function: NameInfoFn,
    address: &libc::sockaddr_un,
    address_len: usize,
    flags: c_int,
    host_len: Option<usize>,
    serv_len: Option<usize>,
) -> LocalOut {
    let mut host = [0xa5; 256];
    let mut serv = [0x5a; 256];
    assert!(host_len.is_none_or(|length| length <= host.len()));
    assert!(serv_len.is_none_or(|length| length <= serv.len()));
    let host_pointer = host_len.map_or(std::ptr::null_mut(), |_| host.as_mut_ptr().cast());
    let serv_pointer = serv_len.map_or(std::ptr::null_mut(), |_| serv.as_mut_ptr().cast());
    // SAFETY: errno is this test thread's host TLS slot. Both implementations
    // share it in the interpose build; no other thread changes its value.
    unsafe { *libc::__errno_location() = libc::EINTR };
    // SAFETY: the live address and buffers cover every advertised extent.
    let ret = unsafe {
        function(
            (address as *const libc::sockaddr_un).cast(),
            address_len as libc::socklen_t,
            host_pointer,
            host_len.unwrap_or(256) as libc::socklen_t,
            serv_pointer,
            serv_len.unwrap_or(256) as libc::socklen_t,
            flags,
        )
    };
    LocalOut {
        ret,
        errno: unsafe { *libc::__errno_location() },
        host,
        serv,
    }
}

fn local_address(path: &[u8]) -> libc::sockaddr_un {
    // SAFETY: every field is an integer or integer array; zero is valid.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    assert!(path.len() <= address.sun_path.len());
    for (slot, &byte) in address.sun_path.iter_mut().zip(path) {
        *slot = byte as c_char;
    }
    address
}

#[test]
fn getnameinfo_local_differential_vs_glibc() {
    let getnameinfo = host_getnameinfo();
    let paths = [
        Vec::new(),
        b"/tmp/frankenlibc-local.sock".to_vec(),
        b"\0abstract-socket".to_vec(),
        b"/tmp/non-utf8-\xff\xfe.sock".to_vec(),
        vec![b'x'; 107],
    ];
    let flag_sets = [
        0,
        libc::NI_NUMERICHOST,
        libc::NI_NUMERICSERV,
        libc::NI_NUMERICHOST | libc::NI_NUMERICSERV,
        libc::NI_DGRAM,
        libc::NI_NOFQDN,
        libc::NI_NAMEREQD,
        libc::NI_NAMEREQD | libc::NI_NUMERICHOST,
        libc::NI_NAMEREQD | libc::NI_NOFQDN,
    ];
    let outputs = [
        (Some(256), Some(256)),
        (Some(256), None),
        (None, Some(256)),
        (None, None),
        (Some(0), Some(256)),
        (Some(256), Some(0)),
        (Some(0), Some(0)),
    ];
    let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let mut compared = 0;
    for path in paths {
        let address = local_address(&path);
        // SUN_LEN excludes the terminating NUL. The backing struct is fully
        // initialized, so the independent host oracle has valid string input.
        for address_len in [size_of::<libc::sockaddr_un>(), offset + path.len()] {
            for flags in flag_sets {
                for (host_len, serv_len) in outputs {
                    let expected = unsafe {
                        call_local(getnameinfo, &address, address_len, flags, host_len, serv_len)
                    };
                    let actual = unsafe {
                        call_local(fl_getnameinfo, &address, address_len, flags, host_len, serv_len)
                    };
                    assert_eq!(
                        actual, expected,
                        "local path={path:?} salen={address_len} flags={flags:#x} \
                         host={host_len:?} service={serv_len:?}"
                    );
                    compared += 1;
                }
            }
        }
    }
    assert_eq!(compared, 630);
    eprintln!("getnameinfo local differential: {compared} host comparisons");
}

#[test]
fn getnameinfo_local_bounds_flags_and_errno_match_glibc() {
    let getnameinfo = host_getnameinfo();
    let path = b"/tmp/local.sock";
    let address = local_address(path);
    let address_len = size_of::<libc::sockaddr_un>();
    let mut compared = 0;
    for flags in [
        0,
        libc::NI_NUMERICHOST | libc::NI_NUMERICSERV,
        libc::NI_NOFQDN,
        libc::NI_NAMEREQD,
    ] {
        for host_len in [0, 1, 8, 9, 10, 64, 256] {
            for serv_len in [0, 1, path.len(), path.len() + 1, 256] {
                let expected = unsafe {
                    call_local(
                        getnameinfo, &address, address_len, flags,
                        Some(host_len), Some(serv_len),
                    )
                };
                let actual = unsafe {
                    call_local(
                        fl_getnameinfo, &address, address_len, flags,
                        Some(host_len), Some(serv_len),
                    )
                };
                assert_eq!(
                    actual, expected,
                    "local overflow flags={flags:#x} host={host_len} service={serv_len}"
                );
                compared += 1;
            }
        }
    }
    for address_len in [0, 1, size_of::<libc::sockaddr_un>()] {
        for flags in [0, 0x100, -1] {
            let expected = unsafe {
                call_local(getnameinfo, &address, address_len, flags, Some(256), Some(256))
            };
            let actual = unsafe {
                call_local(fl_getnameinfo, &address, address_len, flags, Some(256), Some(256))
            };
            assert_eq!(
                actual, expected,
                "local malformed header salen={address_len} flags={flags:#x}"
            );
            compared += 1;
        }
    }
    assert_eq!(compared, 149);
    eprintln!("getnameinfo local bounds differential: {compared} host comparisons");
}

#[test]
fn getnameinfo_local_bounds_unterminated_path_without_host_overread() {
    let address = local_address(&[b'x'; 108]);
    let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    // These objects deliberately lack a C-string terminator. Do not pass them
    // to the host oracle: check FrankenLibC's bounded extension independently.
    for length in [0, 1, 17, 108] {
        let output = unsafe {
            call_local(
                fl_getnameinfo,
                &address,
                offset + length,
                libc::NI_NUMERICHOST | libc::NI_NUMERICSERV,
                Some(256),
                Some(256),
            )
        };
        assert_eq!(output.ret, 0, "unterminated path extent={length}");
        assert_eq!(output.errno, libc::EINTR);
        assert_eq!(&output.host[..10], b"localhost\0");
        assert!(output.serv[..length].iter().all(|&byte| byte == b'x'));
        assert_eq!(output.serv[length], 0);
        assert!(output.serv[length + 1..].iter().all(|&byte| byte == 0x5a));
    }
}
