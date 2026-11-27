//! Differential gate: getservby*/getprotoby* must return the canonical name
//! AND the entry's aliases, exactly like glibc.
//!
//! fl previously returned an empty `s_aliases`/`p_aliases` list and, for
//! getservbyname, echoed the *queried* name instead of the canonical one. So
//! `getservbyname("www","tcp")` returned name="www" aliases=[] where glibc
//! returns name="http" aliases=["www"].
//!
//! Both fl and glibc read the same /etc/services and /etc/protocols, so this
//! compares fl directly against the live host glibc (reached via dlsym to
//! bypass fl's no_mangle interposition) field-for-field, over entries
//! enumerated from the host's real databases.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::resolv_abi as fl;
use std::ffi::{CStr, CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

#[repr(C)]
struct Servent {
    s_name: *mut c_char,
    s_aliases: *mut *mut c_char,
    s_port: c_int,
    s_proto: *mut c_char,
}
#[repr(C)]
struct Protoent {
    p_name: *mut c_char,
    p_aliases: *mut *mut c_char,
    p_proto: c_int,
}

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

unsafe fn sym(lib: *mut c_void, name: &CStr) -> *mut c_void {
    let p = unsafe { dlsym(lib, name.as_ptr()) };
    assert!(!p.is_null(), "dlsym {name:?} failed");
    p
}

fn cstr(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

fn alias_vec(mut pp: *mut *mut c_char) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if pp.is_null() {
        return out;
    }
    unsafe {
        while !(*pp).is_null() {
            out.push(cstr(*pp));
            pp = pp.add(1);
        }
    }
    out
}

// (name, port/number, proto, aliases) extracted from a servent/protoent.
type Snap = (Vec<u8>, c_int, Vec<u8>, Vec<Vec<u8>>);

fn snap_serv(p: *const Servent) -> Option<Snap> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { &*p };
    Some((
        cstr(s.s_name),
        s.s_port,
        cstr(s.s_proto),
        alias_vec(s.s_aliases),
    ))
}
fn snap_proto(p: *const Protoent) -> Option<Snap> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { &*p };
    Some((
        cstr(s.p_name),
        s.p_proto,
        Vec::new(),
        alias_vec(s.p_aliases),
    ))
}

type Getaddrinfo = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const libc::addrinfo,
    *mut *mut libc::addrinfo,
) -> c_int;
type Freeaddrinfo = unsafe extern "C" fn(*mut libc::addrinfo);
type Address = (c_int, c_int, c_int, Vec<u8>);

fn address_result(
    get: Getaddrinfo,
    free: Freeaddrinfo,
    service: &CStr,
    socktype: Option<c_int>,
) -> (c_int, Vec<Address>) {
    let hints = libc::addrinfo {
        ai_flags: libc::AI_NUMERICHOST,
        ai_family: libc::AF_INET,
        ai_socktype: socktype.unwrap_or(0),
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: std::ptr::null_mut(),
        ai_canonname: std::ptr::null_mut(),
        ai_next: std::ptr::null_mut(),
    };
    let mut head = std::ptr::null_mut();
    // SAFETY: the input strings, hints, and result slot are live. A numeric
    // loopback host isolates service resolution from DNS or external traffic.
    let hints = socktype.map_or(std::ptr::null(), |_| &hints as *const _);
    let status = unsafe { get(c"127.0.0.1".as_ptr(), service.as_ptr(), hints, &mut head) };
    let mut addresses = Vec::new();
    if status == 0 {
        let mut next = head;
        while !next.is_null() {
            // SAFETY: a successful lookup owns this complete addrinfo chain.
            let entry = unsafe { &*next };
            assert_eq!(entry.ai_family, libc::AF_INET);
            assert_eq!(
                entry.ai_addrlen as usize,
                std::mem::size_of::<libc::sockaddr_in>()
            );
            // SAFETY: the family and extent above admit the complete address.
            let address = unsafe { &*entry.ai_addr.cast::<libc::sockaddr_in>() };
            let mut bytes = address.sin_port.to_ne_bytes().to_vec();
            bytes.extend_from_slice(&address.sin_addr.s_addr.to_ne_bytes());
            addresses.push((entry.ai_family, entry.ai_socktype, entry.ai_protocol, bytes));
            next = entry.ai_next;
            assert!(addresses.len() < 32, "bounded service result chain");
        }
        // SAFETY: use the allocator paired with this lookup implementation.
        unsafe { free(head) };
    } else {
        assert!(head.is_null(), "failed lookup must not publish a result");
    }
    (status, addresses)
}

fn case_probes(name: &[u8]) -> Vec<Vec<u8>> {
    let mut mixed = name.to_vec();
    if let Some(byte) = mixed.iter_mut().find(|byte| byte.is_ascii_alphabetic()) {
        *byte ^= 0x20;
    }
    let mut probes = vec![name.to_vec(), name.to_ascii_uppercase(), mixed];
    probes.sort();
    probes.dedup();
    probes
}

fn isolated(test: &str) -> bool {
    const CHILD: &str = "FRANKENLIBC_NETDB_KEYS_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(test) {
        return false;
    }
    for mode in ["strict", "hardened"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(CHILD, test)
            .env("FRANKENLIBC_MODE", mode)
            .env_remove("FRANKENLIBC_SERVICES_PATH")
            .env_remove("FRANKENLIBC_PROTOCOLS_PATH")
            .env_remove("FRANKENLIBC_NSSWITCH_CONF")
            .env_remove("LD_PRELOAD")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{test}/{mode}: {:?}\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );
    }
    true
}

#[test]
fn getservby_and_getprotoby_match_glibc() {
    if isolated("getservby_and_getprotoby_match_glibc") {
        return;
    }
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen libc.so.6 failed");

    type SByName = extern "C" fn(*const c_char, *const c_char) -> *mut Servent;
    type SByPort = extern "C" fn(c_int, *const c_char) -> *mut Servent;
    type SEnt = extern "C" fn() -> *mut Servent;
    type Set = extern "C" fn(c_int);
    type End = extern "C" fn();
    type PByName = extern "C" fn(*const c_char) -> *mut Protoent;
    type PEnt = extern "C" fn() -> *mut Protoent;

    let g_sbyname: SByName = unsafe { std::mem::transmute(sym(lib, c"getservbyname")) };
    let g_sbyport: SByPort = unsafe { std::mem::transmute(sym(lib, c"getservbyport")) };
    let g_sent: SEnt = unsafe { std::mem::transmute(sym(lib, c"getservent")) };
    let g_sset: Set = unsafe { std::mem::transmute(sym(lib, c"setservent")) };
    let g_send: End = unsafe { std::mem::transmute(sym(lib, c"endservent")) };
    let g_pbyname: PByName = unsafe { std::mem::transmute(sym(lib, c"getprotobyname")) };
    let g_pent: PEnt = unsafe { std::mem::transmute(sym(lib, c"getprotoent")) };
    let g_pset: Set = unsafe { std::mem::transmute(sym(lib, c"setprotoent")) };
    let g_pend: End = unsafe { std::mem::transmute(sym(lib, c"endprotoent")) };
    let g_gai: Getaddrinfo = unsafe { std::mem::transmute(sym(lib, c"getaddrinfo")) };
    let g_free: Freeaddrinfo = unsafe { std::mem::transmute(sym(lib, c"freeaddrinfo")) };

    // Fail if interposition ever turns the reference arm into the candidate.
    assert_ne!(g_sbyname as *const (), fl::getservbyname as *const ());
    assert_ne!(g_sbyport as *const (), fl::getservbyport as *const ());
    assert_ne!(g_pbyname as *const (), fl::getprotobyname as *const ());
    assert_ne!(g_gai as *const (), fl::getaddrinfo as *const ());

    let mut mismatches = Vec::new();

    // ---- services: enumerate real entries, probe by name (canonical) + port.
    g_sset(1);
    let mut serv_probes: Vec<(Vec<u8>, Vec<u8>, c_int)> = Vec::new(); // (name, proto, port_nbo)
    loop {
        let e = g_sent();
        if e.is_null() {
            break;
        }
        let s = unsafe { &*e };
        let name = cstr(s.s_name);
        let proto = cstr(s.s_proto);
        serv_probes.push((name, proto, s.s_port));
        // Also probe via the first alias (canonical-name behavior).
        let aliases = alias_vec(s.s_aliases);
        if let Some(a) = aliases.first() {
            serv_probes.push((a.clone(), cstr(s.s_proto), s.s_port));
        }
        if serv_probes.len() > 120 {
            break;
        }
    }
    g_send();

    for (name, proto, port_nbo) in &serv_probes {
        for name in case_probes(name) {
            let cn = CString::new(name.clone()).unwrap();
            for proto in case_probes(proto) {
                let cp = CString::new(proto.clone()).unwrap();
                let g = snap_serv(g_sbyname(cn.as_ptr(), cp.as_ptr()));
                let f = snap_serv(unsafe {
                    fl::getservbyname(cn.as_ptr(), cp.as_ptr()).cast::<Servent>()
                });
                if g != f {
                    mismatches.push(format!(
                        "getservbyname({name:?},{proto:?}): glibc={g:?} fl={f:?}"
                    ));
                }
                let g = snap_serv(g_sbyport(*port_nbo, cp.as_ptr()));
                let f = snap_serv(unsafe {
                    fl::getservbyport(*port_nbo, cp.as_ptr()).cast::<Servent>()
                });
                if g != f {
                    mismatches.push(format!(
                        "getservbyport({port_nbo},{proto:?}): glibc={g:?} fl={f:?}"
                    ));
                }
            }
            for socktype in [
                None,
                Some(0),
                Some(libc::SOCK_STREAM),
                Some(libc::SOCK_DGRAM),
            ] {
                let g = address_result(g_gai, g_free, &cn, socktype);
                let f = address_result(fl::getaddrinfo, fl::freeaddrinfo, &cn, socktype);
                if g != f {
                    mismatches.push(format!(
                        "getaddrinfo(127.0.0.1,{name:?},socktype={socktype:?}): glibc={g:?} fl={f:?}"
                    ));
                }
            }
        }
    }

    // ---- protocols: enumerate real entries, probe by name (+ first alias).
    g_pset(1);
    let mut proto_names: Vec<Vec<u8>> = Vec::new();
    loop {
        let e = g_pent();
        if e.is_null() {
            break;
        }
        let s = unsafe { &*e };
        proto_names.push(cstr(s.p_name));
        let aliases = alias_vec(s.p_aliases);
        if let Some(a) = aliases.first() {
            proto_names.push(a.clone());
        }
        if proto_names.len() > 120 {
            break;
        }
    }
    g_pend();

    for name in &proto_names {
        for name in case_probes(name) {
            let cn = CString::new(name.clone()).unwrap();
            let g = snap_proto(g_pbyname(cn.as_ptr()));
            let f = snap_proto(unsafe { fl::getprotobyname(cn.as_ptr()).cast::<Protoent>() });
            if g != f {
                mismatches.push(format!("getprotobyname({name:?}): glibc={g:?} fl={f:?}"));
            }
        }
    }

    // These aliases exercise databases with duplicate TCP ports and UDP-first
    // physical records. Missing distro-specific entries still compare errors
    // against GNU rather than assuming that a service is installed.
    for service in [c"dicom", c"kerberos4", c"kerberos-master"] {
        for socktype in [
            None,
            Some(0),
            Some(libc::SOCK_STREAM),
            Some(libc::SOCK_DGRAM),
        ] {
            let g = address_result(g_gai, g_free, service, socktype);
            let f = address_result(fl::getaddrinfo, fl::freeaddrinfo, service, socktype);
            if g != f {
                mismatches.push(format!(
                    "getaddrinfo(127.0.0.1,{service:?},socktype={socktype:?}): glibc={g:?} fl={f:?}"
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "netdb getXbyY diverged from glibc ({} cases):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

fn gnu_database_line(lib: *mut c_void, input: &[u8], service: bool) -> Option<Snap> {
    type Parse =
        unsafe extern "C" fn(*mut c_char, *mut c_void, *mut c_void, usize, *mut c_int) -> c_int;
    let (name, native) = if service {
        (
            c"_nss_files_parse_servent",
            frankenlibc_abi::unistd_abi::_nss_files_parse_servent as *const (),
        )
    } else {
        (
            c"_nss_files_parse_protoent",
            frankenlibc_abi::unistd_abi::_nss_files_parse_protoent as *const (),
        )
    };
    let parser: Parse = unsafe { std::mem::transmute(sym(lib, name)) };
    assert_ne!(parser as *const (), native);
    // GNU's files reader removes leading C whitespace before invoking its
    // parser. The public owned-record parser must apply the same preparation.
    let leading = input
        .iter()
        .take_while(|&&byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
        .count();
    let input = &input[leading..];
    let mut storage = vec![0u64; 2048];
    let capacity = storage.len() * std::mem::size_of::<u64>();
    assert!(input.len() + 1 < capacity);
    let buffer = storage.as_mut_ptr().cast::<c_char>();
    let mut entry = [0usize; 4];
    let mut error = 717;
    // SAFETY: the aligned allocation contains the terminated input and ample
    // room for GNU's alias pointer table; output fits either netdb layout.
    let status = unsafe {
        std::ptr::copy_nonoverlapping(input.as_ptr(), buffer.cast(), input.len());
        parser(
            buffer,
            entry.as_mut_ptr().cast(),
            buffer.cast(),
            capacity,
            &mut error,
        )
    };
    assert!(
        matches!(status, 0 | 1),
        "ample parser workspace for {input:?}"
    );
    if status == 0 {
        None
    } else if service {
        snap_serv(entry.as_ptr().cast())
    } else {
        snap_proto(entry.as_ptr().cast())
    }
}

fn fixture_file(label: &str, lines: &[&[u8]]) -> std::path::PathBuf {
    use std::io::Write;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-netdb-{label}-{}-{nonce}",
        std::process::id(),
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    for line in lines {
        file.write_all(line).unwrap();
        file.write_all(b"\n").unwrap();
    }
    path
}

fn reentrant_name_result(name: &CStr, protocol: Option<&CStr>, service: bool) -> Option<Snap> {
    let mut entry = [0usize; 4];
    let mut storage = [0u64; 256];
    let mut result = std::ptr::null_mut();
    // SAFETY: the aligned output and scratch area fit every fixture record;
    // the selected source publishes either this output object or null.
    let status = unsafe {
        if service {
            frankenlibc_abi::inet_abi::getservbyname_r(
                name.as_ptr(),
                protocol.map_or(std::ptr::null(), CStr::as_ptr),
                entry.as_mut_ptr().cast(),
                storage.as_mut_ptr().cast(),
                std::mem::size_of_val(&storage),
                &mut result,
            )
        } else {
            frankenlibc_abi::unistd_abi::getprotobyname_r(
                name.as_ptr(),
                entry.as_mut_ptr().cast(),
                storage.as_mut_ptr().cast(),
                std::mem::size_of_val(&storage),
                &mut result,
            )
        }
    };
    assert_eq!(status, 0, "sufficient buffer for {name:?}/{protocol:?}");
    assert!(result.is_null() || result == entry.as_mut_ptr().cast());
    if service {
        snap_serv(result.cast())
    } else {
        snap_proto(result.cast())
    }
}

#[test]
fn public_database_caches_use_gnu_files_grammar_and_exact_keys() {
    if isolated("public_database_caches_use_gnu_files_grammar_and_exact_keys") {
        return;
    }
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null());
    let service_lines: &[&[u8]] = &[
        b" \t\x0bweb-case 0x50/tcp WebCase",
        b"web-case 0120/udp WebCase",
        b"WEB-CASE 81/tcp WEBCASE",
        b"upper-protocol 82/TCP UpperProto",
        b"octal 010/tcp OCTAL",
        b"hex 0x1234/udp HEX",
        b"signed-zero -0/tcp ZERO",
        b"unsigned-max 4294967295/tcp MAX",
        b"wrapped 70000/tcp WRAP",
        b"invalid-octal 08/tcp BAD8",
        b"overflow 4294967296/tcp BAD32",
        b"wide-overflow 18446744073709551616/tcp BAD64",
        b"missing-protocol 84",
        b"missing-alias 84 Alias",
        b"empty-protocol 85/ EMPTYPROTO",
        b"extra-protocol 86/tcp/x More",
        b"terminated 87/tcp before\0after",
        b"trailing-comment 88/tcp keep # ignored",
        b"duplicate 89/udp Dupe",
        b"duplicate 90/tcp Dupe",
        b"duplicate 91/tcp Dupe",
        b"duplicate 92/tcp Dupe",
        b"duplicate 93/tcp Dupe",
        b"duplicate 94/udp Dupe",
    ];
    let protocol_lines: &[&[u8]] = &[
        b" \t\x0btcp-case 6 TcpAlias",
        b"TCP-CASE 7 TCPALIAS",
        b"signed-zero -0 Zero",
        b"unsigned-max 4294967295 MAX",
        b"unsigned-min 2147483648 MIN",
        b"plus +17 PLUS",
        b"decimal 010 DEC",
        b"invalid-hex 0x6 HEX",
        b"overflow 4294967296 BAD",
        b"terminated 33 before\0after",
        b"duplicate 34 DUP",
        b"duplicate 35 DUP",
        b"negative -1 NEG",
    ];
    let mut services = Vec::new();
    let mut protocols = Vec::new();
    for (service, lines, records) in [
        (true, service_lines, &mut services),
        (false, protocol_lines, &mut protocols),
    ] {
        for &line in lines {
            let expected = gnu_database_line(lib, line, service);
            let actual = if service {
                frankenlibc_core::resolv::parse_services_line(line).map(|entry| {
                    (
                        entry.name,
                        c_int::from(entry.port.to_be()),
                        entry.protocol,
                        entry.aliases,
                    )
                })
            } else {
                frankenlibc_core::resolv::parse_protocols_line(line)
                    .map(|entry| (entry.name, entry.number, Vec::new(), entry.aliases))
            };
            assert_eq!(
                actual, expected,
                "public parser service={service} line={line:?}"
            );
            records.extend(expected);
        }
    }
    let services_path = fixture_file("services", service_lines);
    let protocols_path = fixture_file("protocols", protocol_lines);
    // SAFETY: only this selected test runs in its isolated child; no workers
    // or other tests can observe partially selected database paths.
    unsafe {
        std::env::set_var("FRANKENLIBC_SERVICES_PATH", &services_path);
        std::env::set_var("FRANKENLIBC_PROTOCOLS_PATH", &protocols_path);
        for database in [c"services", c"protocols"] {
            assert_eq!(
                frankenlibc_abi::glibc_internal_abi::__nss_configure_lookup(
                    database.as_ptr(),
                    c"files".as_ptr(),
                ),
                0,
            );
        }
    }
    let mut names = vec![
        b"absent".to_vec(),
        b"invalid-octal".to_vec(),
        b"overflow".to_vec(),
    ];
    for record in services.iter().chain(&protocols) {
        names.extend(case_probes(&record.0));
        for alias in &record.3 {
            names.extend(case_probes(alias));
        }
    }
    names.sort();
    names.dedup();
    let matches =
        |entry: &Snap, name: &[u8]| entry.0 == name || entry.3.iter().any(|alias| alias == name);
    for name in names {
        let query = CString::new(name.clone()).unwrap();
        for protocol in [None, Some(c"tcp"), Some(c"udp"), Some(c"TCP"), Some(c"")] {
            let expected = services
                .iter()
                .find(|entry| {
                    matches(entry, &name)
                        && protocol.is_none_or(|filter| entry.2 == filter.to_bytes())
                })
                .cloned();
            let pointer = protocol.map_or(std::ptr::null(), CStr::as_ptr);
            let actual = snap_serv(unsafe { fl::getservbyname(query.as_ptr(), pointer).cast() });
            assert_eq!(actual, expected, "service {name:?}/{protocol:?}");
            assert_eq!(
                reentrant_name_result(&query, protocol, true),
                expected,
                "reentrant service {name:?}/{protocol:?}",
            );
        }
        let expected = protocols
            .iter()
            .find(|entry| matches(entry, &name))
            .cloned();
        let actual = snap_proto(unsafe { fl::getprotobyname(query.as_ptr()).cast() });
        assert_eq!(actual, expected, "protocol {name:?}");
        assert_eq!(
            reentrant_name_result(&query, None, false),
            expected,
            "reentrant protocol {name:?}",
        );
        // Explicit hints keep this synthetic expectation independent of the
        // machine's AI_ADDRCONFIG state. Null hints are compared to live GNU
        // results in the real-database differential above.
        for socktype in [Some(0), Some(libc::SOCK_STREAM), Some(libc::SOCK_DGRAM)] {
            let mut expected = Vec::new();
            for (kind, number, protocol) in [
                (libc::SOCK_STREAM, libc::IPPROTO_TCP, b"tcp"),
                (libc::SOCK_DGRAM, libc::IPPROTO_UDP, b"udp"),
            ] {
                if socktype.is_none_or(|hint| hint == 0 || hint == kind)
                    && let Some(entry) = services
                        .iter()
                        .find(|entry| matches(entry, &name) && entry.2 == protocol)
                {
                    let mut address = (entry.1 as u16).to_ne_bytes().to_vec();
                    address.extend_from_slice(&[127, 0, 0, 1]);
                    expected.push((libc::AF_INET, kind, number, address));
                }
            }
            let status = if expected.is_empty() {
                libc::EAI_SERVICE
            } else {
                0
            };
            let actual = address_result(fl::getaddrinfo, fl::freeaddrinfo, &query, socktype);
            assert_eq!(
                actual,
                (status, expected),
                "service profiles {name:?}/{socktype:?}"
            );
        }
    }
    for record in &services {
        for protocol in [None, Some(c"tcp"), Some(c"udp"), Some(c"TCP"), Some(c"")] {
            let expected = services
                .iter()
                .find(|entry| {
                    entry.1 == record.1
                        && protocol.is_none_or(|filter| entry.2 == filter.to_bytes())
                })
                .cloned();
            let pointer = protocol.map_or(std::ptr::null(), CStr::as_ptr);
            let actual = snap_serv(unsafe { fl::getservbyport(record.1, pointer).cast() });
            assert_eq!(actual, expected, "port {}/{protocol:?}", record.1);
        }
    }
    for record in &protocols {
        let expected = protocols.iter().find(|entry| entry.1 == record.1).cloned();
        let actual = snap_proto(unsafe { fl::getprotobynumber(record.1).cast() });
        assert_eq!(actual, expected, "protocol number {}", record.1);
    }
}
