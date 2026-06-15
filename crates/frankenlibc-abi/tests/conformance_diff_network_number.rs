//! Differential gate for /etc/networks number-field parsing vs glibc.
//!
//! glibc's `nss_files` networks parser feeds the number token to `inet_network`
//! (NOT `inet_aton`), so the field is right-aligned and base-detecting:
//!   * a bare `127` is `0x0000_007f`, not the left-padded `0x7f00_0000`;
//!   * components accept `0x` hex and leading-`0` octal;
//!   * each `.`-separated component must be `<= 0xff`;
//!   * empty components (trailing `.`) and >4 components are rejected.
//!
//! fl previously parsed the number with a decimal-only, inet_aton-style
//! left-shift (`octets[0] << 24` for a single token), so getnetent/getnetbyname/
//! getnetbyaddr produced the wrong `n_net` for every partial-dotted or
//! octal/hex network number. This gate pins `parse_network_number` to the live
//! host `inet_network` reached via dlsym (bypassing fl's no_mangle interposition
//! of the same symbol).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_core::resolv::parse_network_number;
use std::ffi::{CString, c_char, c_int, c_uint, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type InetNetworkFn = extern "C" fn(*const c_char) -> c_uint;

fn host_inet_network() -> InetNetworkFn {
    unsafe {
        let lib = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!lib.is_null(), "dlopen libc.so.6 failed");
        let sym = dlsym(lib, c"inet_network".as_ptr());
        assert!(!sym.is_null(), "dlsym inet_network failed");
        std::mem::transmute::<*mut c_void, InetNetworkFn>(sym)
    }
}

#[test]
fn parse_network_number_matches_glibc_inet_network() {
    let host = host_inet_network();

    // A battery covering: full/partial dotted quads, single tokens, octal,
    // hex, out-of-range octets, empty/trailing-dot, and >4 components.
    let cases = [
        "127",
        "127.0",
        "127.0.0",
        "127.0.0.1",
        "0177",
        "0x7f",
        "10",
        "0xa.0xb",
        "128.66",
        "0",
        "255.255.255.255",
        "1.2.3.4",
        "169.254",
        "169.254.0.0",
        "256",
        "0x7f000001",
        "65536",
        "1.256",
        "127.",
        "1.2.3.4.5",
        "999",
        "0x10.020.8",
        "0xff",
        "08",       // invalid octal digit
        "0xg",      // invalid hex digit
        "",
        "192.168.1",
        "10.0",
    ];

    const INADDR_NONE: u32 = u32::MAX;

    let mut mismatches = Vec::new();
    for &s in &cases {
        let cs = CString::new(s).unwrap();
        let host_val = host(cs.as_ptr());
        let fl_val = parse_network_number(s);

        let ok = match fl_val {
            // glibc rejects -> fl must reject. The sole exception is the
            // ambiguous all-ones result (e.g. "255.255.255.255"), which is a
            // legitimate value that happens to collide with INADDR_NONE.
            Some(v) if host_val == INADDR_NONE => v == INADDR_NONE,
            Some(v) => v == host_val,
            None => host_val == INADDR_NONE,
        };
        if !ok {
            mismatches.push(format!(
                "{s:?}: glibc=0x{host_val:08x} fl={fl_val:?}"
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "parse_network_number diverged from glibc inet_network:\n{}",
        mismatches.join("\n")
    );
}
