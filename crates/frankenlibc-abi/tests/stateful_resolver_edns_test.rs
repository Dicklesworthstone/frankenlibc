//! EDNS/DNSSEC request conformance through the real exported resolver entries.
use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::thread;
use std::time::Duration;

use frankenlibc_abi::resolv_state::{
    RES_DEFNAMES, RES_DNSRCH, RES_INIT, RES_RECURSE, RES_TRUSTAD, State,
};
use frankenlibc_core::resolv::dns::DnsMessage;
mod state {
    pub use frankenlibc_abi::glibc_internal_abi::{
        __res_nclose as close, __res_ninit as init, __res_nmkquery as mkquery,
        __res_nquery as query, __res_nquerydomain as querydomain, __res_nsearch as search,
        __res_nsend as send,
    };
}

fn pointer(state: &mut State) -> *mut c_void {
    (state as *mut State).cast()
}
fn answer(query: &[u8], code: u8, marker: u8) -> Vec<u8> {
    let mut reply = query.to_vec();
    reply[2] |= 0x80;
    reply[3] = 0xa0 | code; // RA and AD, subject to caller trust policy.
    if code == 0 && marker != 0 {
        reply[7] = 1;
        reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, marker]);
    }
    reply
}
fn v4_state(address: SocketAddr) -> State {
    let SocketAddr::V4(address) = address else {
        panic!("IPv4 fixture");
    };
    let mut state = State::zeroed();
    state.options = RES_INIT | RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;
    state.retrans = 1;
    state.retry = 1;
    state.nscount = 1;
    state.nsaddr_list[0].sin_family = libc::AF_INET as _;
    state.nsaddr_list[0].sin_port = address.port().to_be();
    state.nsaddr_list[0].sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
    state.ndots_nsort = if cfg!(target_endian = "little") {
        1
    } else {
        1 << 28
    };
    state
}
fn udp() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
}

// OPT construction belongs to query APIs, not the packet-only mkquery/send APIs.
fn assert_edns_query(sent: &[u8], options: u64, capacity: usize) {
    use frankenlibc_abi::resolv_state::{RES_USE_DNSSEC, RES_USE_EDNS0};
    let decoded = DnsMessage::decode(sent).unwrap();
    let enabled = options & (RES_USE_EDNS0 | RES_USE_DNSSEC) != 0;
    assert_eq!(decoded.additionals.len(), usize::from(enabled));
    assert_eq!(decoded.header.arcount, u16::from(enabled));
    if enabled {
        let opt = &decoded.additionals[0];
        assert!(opt.name.is_empty(), "OPT owner is the DNS root");
        assert_eq!(opt.rtype, 41);
        assert_eq!(opt.rclass, capacity.clamp(512, 1200) as u16);
        assert_eq!(
            opt.ttl,
            if options & RES_USE_DNSSEC != 0 {
                0x8000
            } else {
                0
            }
        );
        assert!(opt.rdata.is_empty());
    }
    assert_eq!(sent[3] & 0x20 != 0, options & RES_TRUSTAD != 0);
}

fn answer_without_opt(sent: &[u8], code: u8, marker: u8) -> Vec<u8> {
    let mut end = 12;
    while sent[end] != 0 {
        end += usize::from(sent[end]) + 1;
    }
    end += 5; // root plus QTYPE and QCLASS
    let mut question = sent[..end].to_vec();
    question[10..12].fill(0);
    answer(&question, code, marker)
}

#[test]
fn edns_and_dnssec_emit_one_bounded_opt_without_granting_ad_trust() {
    use frankenlibc_abi::resolv_state::{RES_USE_DNSSEC, RES_USE_EDNS0};
    for options in [
        0,
        RES_USE_EDNS0,
        RES_USE_DNSSEC,
        RES_USE_EDNS0 | RES_USE_DNSSEC | RES_TRUSTAD,
    ] {
        for capacity in [12usize, 512, 900, 1200, 4096] {
            let socket = udp();
            let mut state = v4_state(socket.local_addr().unwrap());
            state.options |= options;
            let worker = thread::spawn(move || {
                let mut buffer = [0u8; 512];
                let (n, peer) = socket.recv_from(&mut buffer).unwrap();
                assert_edns_query(&buffer[..n], options, capacity);
                let reply = answer_without_opt(&buffer[..n], 0, 81);
                socket.send_to(&reply, peer).unwrap();
                reply
            });
            let mut output = vec![0xa5u8; capacity + 2];
            let n = unsafe {
                state::query(
                    pointer(&mut state),
                    c"example.test".as_ptr(),
                    1,
                    1,
                    output.as_mut_ptr().add(1).cast(),
                    capacity as _,
                )
            };
            let mut expected = worker.join().unwrap();
            if options & RES_TRUSTAD == 0 {
                expected[3] &= !0x20;
            }
            let copied = expected.len().min(capacity);
            assert_eq!(n as usize, copied);
            assert_eq!(&output[1..1 + copied], &expected[..copied]);
            assert_eq!(output[0], 0xa5);
            assert!(output[1 + copied..].iter().all(|&byte| byte == 0xa5));
        }
    }
}

#[test]
fn edns_querydomain_and_search_apply_the_same_opt_to_every_candidate() {
    use frankenlibc_abi::resolv_state::{RES_USE_DNSSEC, RES_USE_EDNS0};
    for search in [false, true] {
        let socket = udp();
        let mut state = v4_state(socket.local_addr().unwrap());
        let options = RES_USE_EDNS0 | RES_USE_DNSSEC;
        state.options |= options;
        state.dnsrch[0] = c"first.test".as_ptr().cast_mut();
        state.dnsrch[1] = c"second.test".as_ptr().cast_mut();
        let worker = thread::spawn(move || {
            let queries = if search {
                vec![
                    (b"host.first.test".as_slice(), 3),
                    (b"host.second.test".as_slice(), 0),
                ]
            } else {
                vec![(b"host.suffix.test".as_slice(), 0)]
            };
            for (owner, code) in queries {
                let mut buffer = [0u8; 512];
                let (n, peer) = socket.recv_from(&mut buffer).unwrap();
                assert_edns_query(&buffer[..n], options, 900);
                assert_eq!(
                    DnsMessage::decode(&buffer[..n]).unwrap().questions[0].qname,
                    owner
                );
                socket
                    .send_to(&answer_without_opt(&buffer[..n], code, 82), peer)
                    .unwrap();
            }
        });
        let mut output = [0u8; 900];
        let n = unsafe {
            if search {
                state::search(
                    pointer(&mut state),
                    c"host".as_ptr(),
                    1,
                    1,
                    output.as_mut_ptr().cast(),
                    900,
                )
            } else {
                state::querydomain(
                    pointer(&mut state),
                    c"host".as_ptr(),
                    c"suffix.test".as_ptr(),
                    1,
                    1,
                    output.as_mut_ptr().cast(),
                    900,
                )
            }
        };
        assert!(n > 0);
        assert_eq!(output[n as usize - 1], 82);
        worker.join().unwrap();
    }
}

#[test]
fn dnssec_opt_survives_udp_to_tcp_fallback_and_a_large_signed_response() {
    use frankenlibc_abi::resolv_state::RES_USE_DNSSEC;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = UdpSocket::bind(listener.local_addr().unwrap()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    // Bound accept even when a regression prevents TCP fallback.
    listener.set_nonblocking(true).unwrap();
    let mut state = v4_state(listener.local_addr().unwrap());
    state.options |= RES_USE_DNSSEC;
    let worker = thread::spawn(move || {
        let mut buffer = [0u8; 512];
        let (n, peer) = socket.recv_from(&mut buffer).unwrap();
        let sent = &buffer[..n];
        assert_edns_query(sent, RES_USE_DNSSEC, 700);
        let mut truncated = answer_without_opt(sent, 0, 0);
        truncated[2] |= 2;
        socket.send_to(&truncated, peer).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "TCP fallback did not connect"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("TCP accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).unwrap();
        let mut tcp_query = vec![0u8; u16::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut tcp_query).unwrap();
        assert_eq!(
            tcp_query, sent,
            "fallback must not remove OPT/DO or change ID"
        );
        let mut reply = answer_without_opt(sent, 0, 83);
        reply[7] = 2;
        // A syntactically framed opaque RRSIG; the resolver must deliver its
        // bytes, not claim it validated a signature or remove DNSSEC data.
        reply.extend_from_slice(&[0xc0, 12, 0, 46, 0, 1, 0, 0, 0, 60, 3, 32]);
        reply.extend_from_slice(&[0x5a; 800]);
        stream
            .write_all(&(reply.len() as u16).to_be_bytes())
            .unwrap();
        for fragment in reply.chunks(7) {
            stream.write_all(fragment).unwrap();
        }
        reply
    });
    let mut output = [0xa5u8; 702];
    let n = unsafe {
        state::query(
            pointer(&mut state),
            c"example.test".as_ptr(),
            1,
            1,
            output.as_mut_ptr().add(1).cast(),
            700,
        )
    };
    let mut expected = worker.join().unwrap();
    assert_eq!(n as usize, expected.len());
    assert!(n > 700);
    expected[2] |= 2;
    expected[3] &= !0x20;
    assert_eq!(&output[1..701], &expected[..700]);
    assert_eq!((output[0], output[701]), (0xa5, 0xa5));
}

#[test]
fn edns_does_not_rewrite_packet_construction_or_raw_send() {
    use frankenlibc_abi::resolv_state::{RES_USE_DNSSEC, RES_USE_EDNS0};
    let socket = udp();
    let mut state = v4_state(socket.local_addr().unwrap());
    state.options |= RES_USE_EDNS0 | RES_USE_DNSSEC | RES_TRUSTAD;
    let mut query = [0xa5u8; 512];
    let n = unsafe {
        state::mkquery(
            pointer(&mut state),
            0,
            c"example.test".as_ptr(),
            1,
            1,
            std::ptr::null(),
            0,
            std::ptr::null(),
            query.as_mut_ptr().cast(),
            512,
        )
    };
    assert_eq!(n, 30);
    assert_eq!(query[11], 0);
    assert_eq!(query[30], 0xa5);
    let sent = query[..n as usize].to_vec();
    let worker = thread::spawn(move || {
        let mut buffer = [0u8; 512];
        let (n, peer) = socket.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..n], sent.as_slice());
        socket.send_to(&answer(&buffer[..n], 0, 84), peer).unwrap();
    });
    let mut output = [0u8; 512];
    let n = unsafe {
        state::send(
            pointer(&mut state),
            query.as_ptr().cast(),
            n,
            output.as_mut_ptr().cast(),
            512,
        )
    };
    assert_eq!(n, 46);
    assert_ne!(output[3] & 0x20, 0);
    worker.join().unwrap();
}

#[test]
fn dnssec_formerr_never_silently_downgrades_the_request() {
    use frankenlibc_abi::resolv_state::RES_USE_DNSSEC;
    let socket = udp();
    let mut state = v4_state(socket.local_addr().unwrap());
    state.options |= RES_USE_DNSSEC;
    let worker = thread::spawn(move || {
        let mut buffer = [0u8; 512];
        let (n, peer) = socket.recv_from(&mut buffer).unwrap();
        assert_edns_query(&buffer[..n], RES_USE_DNSSEC, 512);
        socket
            .send_to(&answer_without_opt(&buffer[..n], 1, 0), peer)
            .unwrap();
        socket
    });
    let mut output = [0xa5u8; 512];
    let n = unsafe {
        state::query(
            pointer(&mut state),
            c"example.test".as_ptr(),
            1,
            1,
            output.as_mut_ptr().cast(),
            512,
        )
    };
    assert_eq!(n, -1);
    assert_eq!(state.res_h_errno, 3);
    assert_eq!(output[3] & 15, 1);
    assert_eq!(output[3] & 0x20, 0);
    let socket = worker.join().unwrap();
    socket.set_nonblocking(true).unwrap();
    assert_eq!(
        socket.recv(&mut output).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn edns_initialization_honors_res_options_without_process_wide_test_races() {
    use frankenlibc_abi::resolv_state::{RES_ROTATE, RES_USE_DNSSEC, RES_USE_EDNS0, RES_USEVC};
    const CHILD: &str = "FRANKENLIBC_EDNS_INIT_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let mut a = State::zeroed();
        let mut b = State::zeroed();
        assert_eq!(unsafe { state::init(pointer(&mut a)) }, 0);
        assert_eq!(unsafe { state::init(pointer(&mut b)) }, 0);
        assert_ne!(a.options & RES_USE_EDNS0, 0);
        assert_eq!(a.options & RES_USE_DNSSEC, 0);
        a.options &= !RES_USE_EDNS0;
        assert_ne!(b.options & RES_USE_EDNS0, 0);
        assert_eq!(unsafe { state::init(pointer(&mut a)) }, 0);
        assert_ne!(a.options & RES_USE_EDNS0, 0);
        assert_eq!((a.retrans, a.retry), (1, 1));
        assert_ne!(a.options & RES_ROTATE, 0);
        assert_ne!(a.options & RES_TRUSTAD, 0);
        assert_ne!(a.options & RES_USEVC, 0);
        let ndots = if cfg!(target_endian = "little") {
            a.ndots_nsort & 15
        } else {
            a.ndots_nsort >> 28
        };
        assert_eq!(ndots, 4);

        // LOCALDOMAIN's leading whitespace denotes a root suffix. With
        // ndots:4, the bare single-label query comes from that suffix, then
        // the second domain is tried. Both TCP requests retain EDNS and AD.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        a.nscount = 1;
        a.nsaddr_list[0] = v4_state(listener.local_addr().unwrap()).nsaddr_list[0];
        let options = a.options;
        let worker = thread::spawn(move || {
            for (name, code, marker) in [
                (b"host".as_slice(), 3, 0),
                (b"host.environment.test".as_slice(), 0, 81),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut size = [0u8; 2];
                stream.read_exact(&mut size).unwrap();
                let mut query = vec![0u8; u16::from_be_bytes(size) as usize];
                stream.read_exact(&mut query).unwrap();
                assert_eq!(DnsMessage::decode(&query).unwrap().questions[0].qname, name);
                assert_edns_query(&query, options, 512);
                let reply = answer_without_opt(&query, code, marker);
                stream
                    .write_all(&(reply.len() as u16).to_be_bytes())
                    .unwrap();
                stream.write_all(&reply).unwrap();
            }
        });
        let mut output = [0u8; 512];
        let length = unsafe {
            state::search(
                pointer(&mut a),
                c"host".as_ptr(),
                1,
                1,
                output.as_mut_ptr().cast(),
                512,
            )
        };
        assert!(length > 0);
        assert_eq!(output[length as usize - 1], 81);
        worker.join().unwrap();
        unsafe {
            state::close(pointer(&mut a));
            state::close(pointer(&mut b));
        }
        return;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "edns_initialization_honors_res_options_without_process_wide_test_races",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("LOCALDOMAIN", " environment.test")
        .env(
            "RES_OPTIONS",
            "edns0 ndots:4 timeout:+1 attempts:1 rotate trust-ad use-vc",
        )
        .status()
        .unwrap();
    assert!(status.success());
}

/// Native host lookup does not call the public res_query APIs. Exercise its
/// actual A/AAAA/PTR wire traffic, including configuration-file/environment
/// selection, so implementing OPT only for caller-owned res_state cannot pass.
#[test]
fn native_host_lookups_honor_edns_configuration_and_preserve_no_aaaa() {
    use frankenlibc_abi::resolv_abi;
    use frankenlibc_abi::resolv_state::RES_USE_EDNS0;
    use std::ffi::CStr;
    use std::ptr;

    const CHILD: &str = "FRANKENLIBC_NATIVE_EDNS_TEST_CHILD";
    if let Some(scenario) = std::env::var_os(CHILD) {
        let no_aaaa = scenario == "no-aaaa";
        // SAFETY: zero initializes valid hints and an empty output list. Both
        // remain live until the returned chain has been read and freed.
        unsafe {
            let mut hints: libc::addrinfo = std::mem::zeroed();
            hints.ai_family = libc::AF_UNSPEC;
            hints.ai_socktype = libc::SOCK_STREAM;
            let mut result = ptr::null_mut();
            assert_eq!(
                resolv_abi::getaddrinfo(
                    c"native-edns.hermetic.test.".as_ptr(),
                    c"443".as_ptr(),
                    &hints,
                    &mut result,
                ),
                0,
            );
            let mut families = Vec::new();
            let mut current = result;
            while !current.is_null() {
                families.push((*current).ai_family);
                match (*current).ai_family {
                    libc::AF_INET => {
                        let address = &*(*current).ai_addr.cast::<libc::sockaddr_in>();
                        assert_eq!(address.sin_addr.s_addr.to_ne_bytes(), [192, 0, 2, 90]);
                    }
                    libc::AF_INET6 => {
                        let address = &*(*current).ai_addr.cast::<libc::sockaddr_in6>();
                        assert_eq!(
                            address.sin6_addr.s6_addr,
                            "2001:db8::90"
                                .parse::<std::net::Ipv6Addr>()
                                .unwrap()
                                .octets(),
                        );
                    }
                    family => panic!("unexpected address family {family}"),
                }
                current = (*current).ai_next;
            }
            resolv_abi::freeaddrinfo(result);
            families.sort_unstable();
            assert_eq!(
                families,
                if no_aaaa {
                    vec![libc::AF_INET]
                } else {
                    vec![libc::AF_INET, libc::AF_INET6]
                },
            );

            if no_aaaa {
                hints.ai_family = libc::AF_INET6;
                result = ptr::null_mut();
                assert_eq!(
                    resolv_abi::getaddrinfo(
                        c"ipv6-only.hermetic.test.".as_ptr(),
                        c"443".as_ptr(),
                        &hints,
                        &mut result,
                    ),
                    libc::EAI_NONAME,
                );
                assert!(
                    result.is_null(),
                    "translated A answers cannot become IPv6 results"
                );
            }

            let mut address: libc::sockaddr_in = std::mem::zeroed();
            address.sin_family = libc::AF_INET as _;
            address.sin_addr.s_addr = u32::from_ne_bytes([192, 0, 2, 90]);
            let mut hostname = [0 as std::ffi::c_char; 128];
            assert_eq!(
                resolv_abi::getnameinfo(
                    (&address as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&address) as _,
                    hostname.as_mut_ptr(),
                    hostname.len() as _,
                    ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                ),
                0,
            );
            assert_eq!(
                CStr::from_ptr(hostname.as_ptr()).to_bytes(),
                b"native-edns.reverse.test"
            );
        }
        return;
    }

    for (scenario, file_options, environment_options, mode, edns, trust_ad) in [
        ("default", "", "", "strict", false, false),
        ("trust-only", "trust-ad", "", "hardened", false, true),
        ("file-edns", "edns0", "", "strict", true, false),
        (
            "environment-edns",
            "",
            "edns0 trust-ad",
            "hardened",
            true,
            true,
        ),
        ("no-aaaa", "edns0 no-aaaa", "", "strict", true, false),
    ] {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "frankenlibc-native-edns-{}-{stamp}-{scenario}",
            std::process::id(),
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let resolver = directory.join("resolv.conf");
        let nsswitch = directory.join("nsswitch.conf");
        std::fs::write(
            &resolver,
            format!("nameserver 127.0.0.1\noptions timeout:1 attempts:1 {file_options}\n"),
        )
        .unwrap();
        std::fs::write(&nsswitch, b"hosts: dns\n").unwrap();
        let socket = udp();
        let port = socket.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            let mut observed = Vec::new();
            for _ in 0..3 {
                let mut buffer = [0u8; 512];
                let (length, peer) = socket.recv_from(&mut buffer).unwrap();
                let sent = &buffer[..length];
                let decoded = DnsMessage::decode(sent).unwrap();
                let question = &decoded.questions[0];
                let projected = question.qname == b"ipv6-only.hermetic.test";
                let enabled = edns && !projected;
                let options = if enabled { RES_USE_EDNS0 } else { 0 }
                    | if trust_ad { RES_TRUSTAD } else { 0 };
                assert_edns_query(sent, options, 1200);
                observed.push((question.qname.clone(), question.qtype));
                let reply = native_host_answer(sent, question.qtype, enabled);
                assert_eq!(reply.len() > 512, enabled, "exercise full EDNS UDP replies");
                socket.send_to(&reply, peer).unwrap();
            }
            observed
        });

        // Only the child sees the private files and ephemeral DNS endpoint.
        // Its configuration is fixed before any ABI path initializes TLS.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_host_lookups_honor_edns_configuration_and_preserve_no_aaaa",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, scenario)
            .env("FRANKENLIBC_RESOLV_CONF", &resolver)
            .env("FRANKENLIBC_NSSWITCH_CONF", &nsswitch)
            .env("FRANKENLIBC_DNS_PORT", port.to_string())
            .env("FRANKENLIBC_MODE", mode)
            .env("LOCALDOMAIN", "")
            .env("RES_OPTIONS", environment_options)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let mut timed_out = false;
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                timed_out = true;
                child.kill().unwrap();
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        let observed = worker.join().expect("native DNS fixture thread");
        assert!(
            !timed_out && output.status.success(),
            "{scenario}: timed_out={timed_out} status={}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"));
        let mut expected = vec![
            (b"native-edns.hermetic.test".to_vec(), 1),
            (b"90.2.0.192.in-addr.arpa".to_vec(), 12),
        ];
        expected.push(if scenario == "no-aaaa" {
            (b"ipv6-only.hermetic.test".to_vec(), 1)
        } else {
            (b"native-edns.hermetic.test".to_vec(), 28)
        });
        let mut observed = observed;
        observed.sort_unstable();
        expected.sort_unstable();
        assert_eq!(observed, expected, "{scenario}: exact native DNS queries");
    }
}

fn native_host_answer(query: &[u8], kind: u16, edns: bool) -> Vec<u8> {
    let mut end = 12;
    while query[end] != 0 {
        end += usize::from(query[end]) + 1;
    }
    end += 5;
    let mut reply = query[..end].to_vec();
    reply[2] |= 0x80;
    reply[3] = 0x80;
    reply[6..12].fill(0);
    reply[7] = 1;
    reply.extend_from_slice(&[0xc0, 12]);
    reply.extend_from_slice(&kind.to_be_bytes());
    reply.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    let data = match kind {
        1 => vec![192, 0, 2, 90],
        28 => "2001:db8::90"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec(),
        12 => b"\x0bnative-edns\x07reverse\x04test\0".to_vec(),
        other => panic!("unexpected native DNS question {other}"),
    };
    reply.extend_from_slice(&(data.len() as u16).to_be_bytes());
    reply.extend_from_slice(&data);
    if edns {
        reply[11] = 2;
        reply.extend_from_slice(&[0, 0, 41, 4, 176, 0, 0, 0, 0, 0, 0]);
        // A private-use opaque RR makes this a valid >512-byte response.
        // The resolver must retain the complete datagram while returning
        // only the requested address/PTR data, not the additional RR.
        reply.extend_from_slice(&[0xc0, 12, 255, 0, 0, 1, 0, 0, 0, 60, 2, 88]);
        reply.extend_from_slice(&[0xa5; 600]);
    }
    reply
}
