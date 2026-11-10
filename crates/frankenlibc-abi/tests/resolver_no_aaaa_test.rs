//! RES_NOAAAA conformance against an independent, provider-checked glibc oracle.
//! Every network request terminates at a bounded loopback DNS fixture.

#![cfg(target_os = "linux")]

use std::ffi::{c_char, c_int, c_void};
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use frankenlibc_abi::resolv_state::{
    Extension, RES_INIT, RES_NOAAAA, RES_RECURSE, RES_USE_DNSSEC, RES_USE_EDNS0, State,
};
use frankenlibc_abi::{glibc_internal_abi as abi, resolv_abi};
use frankenlibc_core::resolv::dns::DnsMessage;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Query =
    unsafe extern "C" fn(*mut c_void, *const c_char, c_int, c_int, *mut c_void, c_int) -> c_int;
type Send = unsafe extern "C" fn(*mut c_void, *const c_void, c_int, *mut c_void, c_int) -> c_int;
type Close = unsafe extern "C" fn(*mut c_void);
type HError = unsafe extern "C" fn() -> *mut c_int;

fn configured(endpoint: SocketAddr) -> State {
    let SocketAddr::V4(endpoint) = endpoint else {
        panic!("IPv4 fixture")
    };
    let mut state = State::zeroed();
    state.options = RES_INIT | RES_RECURSE | RES_NOAAAA;
    state.retrans = 1;
    state.retry = 1;
    state.vcsock = -1;
    state.extension.ext = Extension {
        nscount: 0,
        nsmap: [0, 1, 2],
        nssocks: [-1; 3],
        nscount6: 0,
        nsinit: 0,
        nsaddrs: [std::ptr::null_mut(); 3],
        reserved: [0; 2],
    };
    state.nscount = 1;
    state.nsaddr_list[0].sin_family = libc::AF_INET as _;
    state.nsaddr_list[0].sin_port = endpoint.port().to_be();
    state.nsaddr_list[0].sin_addr.s_addr = u32::from_ne_bytes(endpoint.ip().octets());
    state
}

fn question_end(wire: &[u8]) -> usize {
    let mut end = 12;
    while wire[end] != 0 {
        end += usize::from(wire[end]) + 1;
    }
    end + 5
}

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    result: c_int,
    h_error: c_int,
    state_error: c_int,
    question: Vec<u8>,
    response: Vec<u8>,
}

fn observe(
    query: Query,
    send: Send,
    close: Close,
    h_error: HError,
    raw: bool,
    class: u8,
    code: u8,
    edns: bool,
) -> Observation {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut state = configured(socket.local_addr().unwrap());
    if edns {
        state.options |= RES_USE_EDNS0 | RES_USE_DNSSEC;
    }
    let worker = thread::spawn(move || {
        let mut buffer = [0u8; 512];
        let (length, peer) = socket.recv_from(&mut buffer).unwrap();
        let request = &buffer[..length];
        let decoded = DnsMessage::decode(request).unwrap();
        assert_eq!(decoded.questions[0].qtype, if class == 1 { 1 } else { 28 });
        assert_eq!(decoded.questions[0].qclass, u16::from(class));
        assert_eq!(
            decoded.header.arcount,
            u16::from(edns && !raw && class != 1)
        );
        let mut response = request[..question_end(request)].to_vec();
        response[2] |= 0x80;
        response[3] = 0x80 | code;
        response[10..12].fill(0);
        if code == 0 {
            response[7] = 1;
            let data: &[u8] = if class == 1 {
                &[192, 0, 2, 42]
            } else {
                &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42]
            };
            response.extend_from_slice(&[
                0xc0,
                12,
                0,
                if class == 1 { 1 } else { 28 },
                0,
                class,
                0,
                0,
                0,
                60,
                0,
                data.len() as u8,
            ]);
            response.extend_from_slice(data);
        }
        socket.send_to(&response, peer).unwrap();
        let mut request = request.to_vec();
        request[..2].fill(0); // Entropy-generated transaction IDs are intentionally distinct.
        request
    });
    let pointer = (&mut state as *mut State).cast();
    let mut output = [0xa5u8; 514];
    let mut wire = vec![0x31, 0x29, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    wire.extend_from_slice(b"\x07example\x04test\0\0\x1c\0");
    wire.push(class);
    let original = wire.clone();
    // SAFETY: each provider receives a live, aligned public resolver state,
    // NUL-terminated input, and bounded caller-owned buffers. Its own h_errno
    // pointer and close entry are used; no provider frees another's state.
    let (result, h_error, state_error) = unsafe {
        *h_error() = 87;
        state.res_h_errno = 89;
        let result = if raw {
            send(
                pointer,
                wire.as_ptr().cast(),
                wire.len() as _,
                output.as_mut_ptr().add(1).cast(),
                512,
            )
        } else {
            query(
                pointer,
                c"example.test".as_ptr(),
                class.into(),
                28,
                output.as_mut_ptr().add(1).cast(),
                512,
            )
        };
        let errors = (*h_error(), state.res_h_errno);
        close(pointer);
        (result, errors.0, errors.1)
    };
    assert_eq!(wire, original, "res_nsend cannot mutate its const query");
    assert_eq!((output[0], output[513]), (0xa5, 0xa5));
    let question = worker.join().unwrap();
    let valid = if result >= 0 {
        result as usize
    } else {
        question_end(&output[1..])
    };
    let mut response = output[1..=valid].to_vec();
    response[..2].fill(0);
    if class == 1 {
        assert_eq!(response.len(), wire.len());
        assert_eq!(&response[6..12], &[0; 6]);
        assert_eq!(&response[26..30], &[0, 28, 0, 1]);
        assert_eq!(response[3] & 15, code);
        if !raw {
            assert_eq!(result, -1);
            assert_eq!(state_error, if code == 3 { 1 } else { 4 });
        }
    }
    Observation {
        result,
        h_error,
        state_error,
        question,
        response,
    }
}

#[test]
fn no_aaaa_raw_and_query_match_glibc_for_nodata_nxdomain_edns_and_non_in() {
    // SAFETY: each type exactly matches the named C resolver declaration.
    // host_fn verifies the oracle is not the candidate export.
    let (host_query, host_send, host_close, host_h_error): (Query, Send, Close, HError) = unsafe {
        (
            dlsym_oracle::host_fn(c"res_nquery", abi::__res_nquery as *const ()),
            dlsym_oracle::host_fn(c"res_nsend", abi::__res_nsend as *const ()),
            dlsym_oracle::host_fn(c"__res_nclose", abi::__res_nclose as *const ()),
            dlsym_oracle::host_fn(
                c"__h_errno_location",
                resolv_abi::__h_errno_location as *const (),
            ),
        )
    };
    for raw in [false, true] {
        for class in [1, 3] {
            for code in [0, 3] {
                for edns in [false, true] {
                    let candidate = observe(
                        abi::__res_nquery,
                        abi::__res_nsend,
                        abi::__res_nclose,
                        resolv_abi::__h_errno_location,
                        raw,
                        class,
                        code,
                        edns,
                    );
                    let host = observe(
                        host_query,
                        host_send,
                        host_close,
                        host_h_error,
                        raw,
                        class,
                        code,
                        edns,
                    );
                    assert_eq!(
                        candidate, host,
                        "raw={raw} class={class} rcode={code} edns={edns}"
                    );
                }
            }
        }
    }
}

fn addresses(node: Option<&std::ffi::CStr>, family: c_int, flags: c_int) -> (c_int, Vec<String>) {
    // SAFETY: every input and result span has the public getaddrinfo layout;
    // the returned linked list remains live until its provider frees it.
    unsafe {
        let mut hints: libc::addrinfo = std::mem::zeroed();
        hints.ai_family = family;
        hints.ai_socktype = libc::SOCK_STREAM;
        hints.ai_flags = flags;
        let mut result = std::ptr::null_mut();
        let rc = resolv_abi::getaddrinfo(
            node.map_or(std::ptr::null(), |name| name.as_ptr()),
            c"80".as_ptr(),
            &hints,
            &mut result,
        );
        let mut addresses = Vec::new();
        let mut cursor = result;
        while !cursor.is_null() {
            let item = &*cursor;
            addresses.push(match item.ai_family {
                libc::AF_INET => {
                    let address = &*item.ai_addr.cast::<libc::sockaddr_in>();
                    std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()).to_string()
                }
                libc::AF_INET6 => {
                    let address = &*item.ai_addr.cast::<libc::sockaddr_in6>();
                    std::net::Ipv6Addr::from(address.sin6_addr.s6_addr).to_string()
                }
                family => panic!("unexpected family {family}"),
            });
            cursor = item.ai_next;
        }
        resolv_abi::freeaddrinfo(result);
        addresses.sort();
        (rc, addresses)
    }
}

#[test]
fn no_aaaa_configuration_controls_dns_without_disabling_local_ipv6() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    const CHILD: &str = "FRANKENLIBC_NO_AAAA_TEST_CHILD";
    if let Some(mode) = std::env::var_os(CHILD) {
        let enabled = mode == "enabled";
        type Init = unsafe extern "C" fn(*mut c_void) -> c_int;
        // SAFETY: exact C signatures; host_fn rejects the candidate address.
        let (host_init, host_close): (Init, Close) = unsafe {
            (
                dlsym_oracle::host_fn(c"__res_ninit", abi::__res_ninit as *const ()),
                dlsym_oracle::host_fn(c"__res_nclose", abi::__res_nclose as *const ()),
            )
        };
        let mut candidate = State::zeroed();
        let mut host = State::zeroed();
        // Stateful initialization reads /etc/resolv.conf like glibc; the
        // native address path also supports the isolated test config path.
        // SAFETY: distinct aligned caller-owned states, paired with each
        // provider's own initialization and close routines.
        unsafe {
            assert_eq!(abi::__res_ninit((&mut candidate as *mut State).cast()), 0);
            assert_eq!(host_init((&mut host as *mut State).cast()), 0);
            assert_eq!(candidate.options & RES_NOAAAA, host.options & RES_NOAAAA);
            abi::__res_nclose((&mut candidate as *mut State).cast());
            host_close((&mut host as *mut State).cast());
        }
        let ipv4 = "192.0.2.55".to_owned();
        let ipv6 = "2001:db8::55".to_owned();
        let mut dual = vec![ipv4.clone()];
        if !enabled {
            dual.push(ipv6.clone());
        }
        assert_eq!(addresses(Some(c"dns.test."), libc::AF_UNSPEC, 0), (0, dual));
        assert_eq!(
            addresses(Some(c"dns.test."), libc::AF_INET, 0),
            (0, vec![ipv4])
        );
        assert_eq!(
            addresses(Some(c"dns.test."), libc::AF_INET6, 0),
            if enabled {
                (libc::EAI_NONAME, vec![])
            } else {
                (0, vec![ipv6.clone()])
            }
        );
        assert_eq!(
            addresses(Some(c"dns.test."), libc::AF_INET6, libc::AI_V4MAPPED),
            (
                0,
                vec![if enabled {
                    "::ffff:192.0.2.55".to_owned()
                } else {
                    ipv6
                }]
            )
        );
        assert_eq!(
            addresses(Some(c"files.test"), libc::AF_INET6, 0),
            (0, vec!["2001:db8::99".to_owned()])
        );
        assert_eq!(
            addresses(Some(c"2001:db8::77"), libc::AF_INET6, libc::AI_NUMERICHOST),
            (0, vec!["2001:db8::77".to_owned()])
        );
        assert_eq!(
            addresses(None, libc::AF_INET6, libc::AI_PASSIVE),
            (0, vec!["::".to_owned()])
        );
        return;
    }

    let directory =
        std::env::temp_dir().join(format!("frankenlibc-no-aaaa-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let config = directory.join("resolv.conf");
    let hosts = directory.join("hosts");
    let nsswitch = directory.join("nsswitch.conf");
    std::fs::write(&hosts, b"2001:db8::99 files.test\n").unwrap();
    std::fs::write(&nsswitch, b"hosts: files dns\n").unwrap();
    for (file_option, environment, enabled) in [
        ("no-aaaa", "", true),
        ("no-aaaa", "-no-aaaa", false),
        ("", "no-aaaa", true),
        ("", "no-aaaa -no-aaaa no-aaaa", true),
    ] {
        std::fs::write(
            &config,
            format!("nameserver 127.0.0.1\noptions timeout:1 attempts:1 {file_option}\n"),
        )
        .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        socket
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            let mut buffer = [0u8; 512];
            while !server_stop.load(Ordering::Relaxed) {
                let (length, peer) = match socket.recv_from(&mut buffer) {
                    Ok(value) => value,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => panic!("fixture receive: {error}"),
                };
                let query = &buffer[..length];
                let decoded = DnsMessage::decode(query).unwrap();
                assert_eq!(decoded.questions[0].qname, b"dns.test");
                let kind = decoded.questions[0].qtype;
                assert!(matches!(kind, 1 | 28));
                requests.push(kind);
                let data: &[u8] = if kind == 1 {
                    &[192, 0, 2, 55]
                } else {
                    &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x55]
                };
                let mut response = query[..question_end(query)].to_vec();
                response[2] |= 0x80;
                response[3] = 0x80;
                response[7] = 1;
                response[10..12].fill(0);
                response.extend_from_slice(&[
                    0xc0,
                    12,
                    0,
                    kind as u8,
                    0,
                    1,
                    0,
                    0,
                    0,
                    60,
                    0,
                    data.len() as u8,
                ]);
                response.extend_from_slice(data);
                socket.send_to(&response, peer).unwrap();
            }
            requests
        });
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "no_aaaa_configuration_controls_dns_without_disabling_local_ipv6",
                "--nocapture",
            ])
            .env(CHILD, if enabled { "enabled" } else { "disabled" })
            .env("FRANKENLIBC_RESOLV_CONF", &config)
            .env("FRANKENLIBC_HOSTS_PATH", &hosts)
            .env("FRANKENLIBC_NSSWITCH_CONF", &nsswitch)
            .env("FRANKENLIBC_DNS_PORT", port.to_string())
            .env("RES_OPTIONS", environment)
            .env("LOCALDOMAIN", "")
            .env_remove("HOSTALIASES")
            .status();
        stop.store(true, Ordering::Relaxed);
        let requests = worker.join().unwrap();
        assert!(
            result.unwrap().success(),
            "file={file_option:?} RES_OPTIONS={environment:?}"
        );
        assert_eq!(
            requests.len(),
            5,
            "DNS only; files/numeric/passive lookups send nothing"
        );
        if enabled {
            assert!(
                requests.iter().all(|&kind| kind == 1),
                "AAAA escaped suppression: {requests:?}"
            );
        } else {
            assert_eq!(requests.iter().filter(|&&kind| kind == 28).count(), 3);
        }
    }
}
