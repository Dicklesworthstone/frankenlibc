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

unsafe extern "C" {
    fn getnameinfo(
        sa: *const libc::sockaddr,
        salen: libc::socklen_t,
        host: *mut c_char,
        hostlen: libc::socklen_t,
        serv: *mut c_char,
        servlen: libc::socklen_t,
        flags: c_int,
    ) -> c_int;
}

use frankenlibc_abi::resolv_abi::getnameinfo as fl_getnameinfo;

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
            if r.next() % 5 == 0 {
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
            sin6.sin6_scope_id = if r.next() % 3 == 0 {
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
    eprintln!("getnameinfo numeric differential fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
