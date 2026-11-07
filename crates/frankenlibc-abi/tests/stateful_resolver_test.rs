//! Direct tests of native caller-owned resolver state, independent of host DNS.
use std::ffi::{CStr, c_void};
use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::thread;
use std::time::Duration;

use frankenlibc_abi::resolv_state::{
    Extension, RES_DEFNAMES, RES_DNSRCH, RES_IGNTC, RES_INIT, RES_RECURSE, RES_TRUSTAD, RES_USEVC,
    State,
};
// Exercise the real exported entry bodies, not only their native delegates.
mod state {
    pub use frankenlibc_abi::glibc_internal_abi::{
        __res_nclose as close, __res_ninit as init, __res_nmkquery as mkquery,
        __res_nquery as query, __res_nquerydomain as querydomain, __res_nsearch as search,
        __res_nsend as send,
    };
}
use frankenlibc_core::resolv::dns::DnsMessage;

fn pointer(state: &mut State) -> *mut c_void {
    (state as *mut State).cast()
}
fn wire() -> Vec<u8> {
    let mut wire = vec![0; 12];
    wire[0..6].copy_from_slice(&[0x31, 0x29, 1, 0, 0, 1]);
    wire.extend_from_slice(b"\x07example\x04test\0\0\x01\0\x01");
    wire
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
fn responder(socket: UdpSocket, code: u8, marker: u8) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0; 1024];
        let (n, peer) = socket.recv_from(&mut buffer).unwrap();
        socket
            .send_to(&answer(&buffer[..n], code, marker), peer)
            .unwrap();
    })
}

#[test]
fn hostaliases_search_queries_one_target_and_honors_each_states_options() {
    use frankenlibc_abi::resolv_state::RES_NOALIASES;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const CHILD: &str = "FRANKENLIBC_HOSTALIASES_SEARCH_TEST_CHILD";
    const ENDPOINT: &str = "FRANKENLIBC_HOSTALIASES_SEARCH_TEST_ENDPOINT";
    if std::env::var_os(CHILD).is_some() {
        let endpoint: SocketAddr = std::env::var(ENDPOINT).unwrap().parse().unwrap();
        let configured = || {
            let mut state = v4_state(endpoint);
            state.ndots_nsort = if cfg!(target_endian = "little") {
                4
            } else {
                4 << 28
            };
            state.dnsrch[0] = c"suffix.test".as_ptr().cast_mut();
            state
        };
        let mut local = configured();
        let options = local.options;
        let mut output = [0u8; 512];
        for (name, flags, success, host_error) in [
            (c"sHoRt", options, true, 1),
            (c"short", options & !(RES_DEFNAMES | RES_DNSRCH), true, 1),
            (c"negative", options, false, 1),
            (c"chain", options, false, 1),
            (c"dotted.alias", options, false, 1),
            (c"short.", options, false, 1),
            (c"invalid", options, false, 3),
            (c"short", options | RES_NOALIASES, false, 1),
        ] {
            local.options = flags;
            let result = unsafe {
                state::search(
                    pointer(&mut local),
                    name.as_ptr(),
                    1,
                    1,
                    output.as_mut_ptr().cast(),
                    output.len() as _,
                )
            };
            assert_eq!(result > 0, success, "{name:?} options={flags:#x}");
            assert_eq!(local.res_h_errno, host_error, "{name:?}");
            if success {
                assert_eq!(output[result as usize - 1], 81);
            }
        }

        // Plain query has no alias/search preprocessing, even with aliases
        // enabled in the same state.
        local.options = options;
        assert_eq!(
            unsafe {
                state::query(
                    pointer(&mut local),
                    c"short".as_ptr(),
                    1,
                    1,
                    output.as_mut_ptr().cast(),
                    output.len() as _,
                )
            },
            -1
        );
        assert_eq!(local.res_h_errno, 1);

        // The legacy global entry shares the same search implementation and
        // observes its own public option bit on each call.
        let global = unsafe { frankenlibc_abi::glibc_internal_abi::__res_state() };
        unsafe {
            state::close(global);
            *global.cast::<State>() = configured();
        }
        for disabled in [false, true] {
            if disabled {
                unsafe { (*global.cast::<State>()).options |= RES_NOALIASES };
            }
            let result = unsafe {
                frankenlibc_abi::unistd_abi::res_search(
                    c"short".as_ptr(),
                    1,
                    1,
                    output.as_mut_ptr().cast(),
                    output.len() as _,
                )
            };
            assert_eq!(result > 0, !disabled);
            assert_eq!(unsafe { (*global.cast::<State>()).res_h_errno }, 1);
        }
        unsafe { state::close(global) };
        return;
    }

    let aliases = std::env::temp_dir().join(format!(
        "frankenlibc-state-hostaliases-{}.txt",
        std::process::id()
    ));
    std::fs::write(
        &aliases,
        b"broken\nSHORT target.test\nnegative missing.test\nchain next\nnext target.test\ndotted.alias target.test\ninvalid invalid..name\n",
    )
    .unwrap();
    let socket = udp();
    let endpoint = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_server = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        let mut observed = Vec::new();
        let mut buffer = [0u8; 512];
        while !stop_server.load(Ordering::Relaxed) {
            let (n, peer) = match socket.recv_from(&mut buffer) {
                Ok(received) => received,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) => panic!("DNS fixture: {error}"),
            };
            let message = DnsMessage::decode(&buffer[..n]).unwrap();
            let question = &message.questions[0];
            assert_eq!((question.qtype, question.qclass), (1, 1));
            let found = question.qname == b"target.test";
            observed.push(question.qname.clone());
            socket
                .send_to(
                    &answer(
                        &buffer[..n],
                        if found { 0 } else { 3 },
                        if found { 81 } else { 0 },
                    ),
                    peer,
                )
                .unwrap();
        }
        observed
    });
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "hostaliases_search_queries_one_target_and_honors_each_states_options",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env(ENDPOINT, endpoint.to_string())
        .env("HOSTALIASES", &aliases)
        .env("FRANKENLIBC_MODE", "strict")
        .output()
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    let observed = worker.join().unwrap();
    let _ = std::fs::remove_file(aliases);
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = [
        "target.test",
        "target.test",
        "missing.test",
        "next",
        "dotted.alias.suffix.test",
        "dotted.alias",
        "short",
        "short.suffix.test",
        "short",
        "short",
        "target.test",
        "short.suffix.test",
        "short",
    ]
    .map(|name| name.as_bytes().to_vec());
    assert_eq!(observed, expected);
}

#[test]
fn public_state_layout_matches_linux_64_bit_header() {
    if cfg!(target_pointer_width = "64") {
        assert_eq!(std::mem::size_of::<State>(), 568);
        assert_eq!(std::mem::align_of::<State>(), 8);
        assert_eq!(std::mem::offset_of!(State, nsaddr_list), 20);
        assert_eq!(std::mem::offset_of!(State, dnsrch), 72);
        assert_eq!(std::mem::offset_of!(State, defdname), 128);
        assert_eq!(std::mem::offset_of!(State, res_h_errno), 496);
        assert_eq!(std::mem::offset_of!(State, extension), 512);
        assert_eq!(std::mem::offset_of!(Extension, nsaddrs), 24);
    }
}

#[test]
fn construction_uses_each_states_flags_type_class_and_id_slot() {
    let mut state = State::zeroed();
    for (options, flags) in [
        (0, 0u16),
        (RES_RECURSE, 0x100),
        (RES_TRUSTAD, 0x20),
        (RES_RECURSE | RES_TRUSTAD, 0x120),
    ] {
        state.options = options;
        let mut out = [0xa5; 512];
        let n = unsafe {
            state::mkquery(
                pointer(&mut state),
                0,
                c"example.test".as_ptr(),
                3,
                16,
                std::ptr::null(),
                0,
                std::ptr::null(),
                out.as_mut_ptr().cast(),
                512,
            )
        };
        assert_eq!(n, 30);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), flags);
        assert_eq!(state.id, u16::from_ne_bytes([out[0], out[1]]));
        assert_eq!(&out[26..30], &[0, 16, 0, 3]);
        assert_eq!(out[30], 0xa5);
        assert_eq!(state.options, options, "mkquery must not initialize state");
    }
}

#[test]
fn notify_completion_and_overlapping_construction_are_supported() {
    let mut state = State::zeroed();
    state.options = RES_RECURSE;
    let mut output = [0u8; 512];
    output[..13].copy_from_slice(b"example.test\0");
    let n = unsafe {
        state::mkquery(
            pointer(&mut state),
            4,
            output.as_ptr().cast(),
            1,
            6,
            c"edge.test".as_ptr().cast(),
            0,
            std::ptr::null(),
            output.as_mut_ptr().cast(),
            512,
        )
    };
    assert_eq!(n, 47);
    assert_eq!(u16::from_be_bytes([output[2], output[3]]), 0x2100);
    assert_eq!(output[11], 1);
    let message = DnsMessage::decode(&output[..n as usize]).unwrap();
    assert_eq!(message.questions[0].qname, b"example.test");
    assert_eq!(message.additionals[0].name, b"edge.test");
    assert_eq!(message.additionals[0].rtype, 10);
}

#[test]
fn independent_states_use_their_own_nameserver_ports_and_trust_flags() {
    let first = udp();
    let second = udp();
    let mut a = v4_state(first.local_addr().unwrap());
    let mut b = v4_state(second.local_addr().unwrap());
    b.options |= RES_TRUSTAD;
    let threads = [responder(first, 0, 11), responder(second, 0, 22)];
    let query = wire();
    for (state, marker, ad) in [(&mut a, 11, false), (&mut b, 22, true)] {
        let mut output = [0u8; 512];
        let n = unsafe {
            state::send(
                pointer(state),
                query.as_ptr().cast(),
                query.len() as _,
                output.as_mut_ptr().cast(),
                512,
            )
        };
        assert!(n > 0);
        assert_eq!(output[n as usize - 1], marker);
        assert_eq!(output[3] & 0x20 != 0, ad);
    }
    for worker in threads {
        worker.join().unwrap();
    }
}

#[test]
fn caller_ipv6_endpoint_is_borrowed_not_freed_by_close() {
    let socket = UdpSocket::bind("[::1]:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    address.sin6_family = libc::AF_INET6 as _;
    address.sin6_port = socket.local_addr().unwrap().port().to_be();
    address.sin6_addr.s6_addr = Ipv6Addr::LOCALHOST.octets();
    let mut state = State::zeroed();
    state.options = RES_INIT;
    state.retrans = 1;
    state.retry = 1;
    state.nscount = 1;
    unsafe {
        state.extension.ext.nsaddrs[0] = &mut address;
    }
    let worker = responder(socket, 0, 42);
    let query = wire();
    let mut output = [0u8; 512];
    let n = unsafe {
        state::send(
            pointer(&mut state),
            query.as_ptr().cast(),
            query.len() as _,
            output.as_mut_ptr().cast(),
            512,
        )
    };
    assert!(n > 0);
    assert_eq!(output[n as usize - 1], 42);
    unsafe {
        state::close(pointer(&mut state));
        state::close(pointer(&mut state));
    }
    assert!(std::ptr::eq(
        unsafe { state.extension.ext.nsaddrs[0] },
        &address
    ));
    worker.join().unwrap();
}

#[test]
fn state_forced_tcp_retains_full_length_and_supports_buffer_reuse() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut state = v4_state(listener.local_addr().unwrap());
    state.options |= RES_USEVC;
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut prefix = [0; 2];
        stream.read_exact(&mut prefix).unwrap();
        let mut query = vec![0; u16::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut query).unwrap();
        let reply = answer(&query, 0, 73);
        stream
            .write_all(&(reply.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(&reply).unwrap();
    });
    let query = wire();
    let mut both = [0xa5u8; 512];
    both[..query.len()].copy_from_slice(&query);
    let n = unsafe {
        state::send(
            pointer(&mut state),
            both.as_ptr().cast(),
            query.len() as _,
            both.as_mut_ptr().cast(),
            12,
        )
    };
    assert_eq!(n, query.len() as i32 + 16);
    assert_ne!(both[2] & 2, 0);
    assert_eq!(&both[12..query.len()], &query[12..]);
    assert_eq!(both[query.len()], 0xa5);
    worker.join().unwrap();
}

#[test]
fn state_ignore_truncation_does_not_attempt_tcp() {
    let socket = udp();
    let mut state = v4_state(socket.local_addr().unwrap());
    state.options |= RES_IGNTC;
    let worker = thread::spawn(move || {
        let mut b = [0; 512];
        let (n, peer) = socket.recv_from(&mut b).unwrap();
        let mut reply = answer(&b[..n], 0, 0);
        reply[2] |= 2;
        socket.send_to(&reply, peer).unwrap();
    });
    let query = wire();
    let mut out = [0u8; 512];
    let n = unsafe {
        state::send(
            pointer(&mut state),
            query.as_ptr().cast(),
            query.len() as _,
            out.as_mut_ptr().cast(),
            512,
        )
    };
    assert_eq!(n, query.len() as i32);
    assert_ne!(out[2] & 2, 0);
    let mut expected = answer(&query, 0, 0);
    expected[2] |= 2;
    expected[3] &= !0x20;
    assert_eq!(&out[..n as usize], expected.as_slice());
    assert!(out[n as usize..].iter().all(|&byte| byte == 0));
    worker.join().unwrap();
}

#[test]
fn query_distinguishes_positive_nxdomain_and_nodata_in_caller_error_slot() {
    for (rcode, marker, herror) in [(0, 7, 0), (3, 0, 1), (0, 0, 4)] {
        let socket = udp();
        let mut state = v4_state(socket.local_addr().unwrap());
        state.res_h_errno = 99;
        let worker = responder(socket, rcode, marker);
        let mut output = [0xa5; 512];
        unsafe {
            *frankenlibc_abi::resolv_abi::__h_errno_location() = 99;
        }
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
        assert_eq!(n > 0, herror == 0);
        let expected = if herror == 0 { 99 } else { herror };
        assert_eq!(state.res_h_errno, expected);
        assert_eq!(
            unsafe { *frankenlibc_abi::resolv_abi::__h_errno_location() },
            expected
        );
        assert_ne!(output[2] & 0x80, 0, "negative replies must still be copied");
        assert_eq!(output[3] & 15, rcode);
        worker.join().unwrap();
    }
}

#[test]
fn querydomain_uses_exact_combined_name_without_searching() {
    let socket = udp();
    let mut state = v4_state(socket.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let mut b = [0; 512];
        let (n, peer) = socket.recv_from(&mut b).unwrap();
        assert_eq!(
            DnsMessage::decode(&b[..n]).unwrap().questions[0].qname,
            b"host.suffix.test"
        );
        socket.send_to(&answer(&b[..n], 0, 7), peer).unwrap();
    });
    let mut output = [0u8; 512];
    assert!(
        unsafe {
            state::querydomain(
                pointer(&mut state),
                c"host".as_ptr(),
                c"suffix.test".as_ptr(),
                1,
                1,
                output.as_mut_ptr().cast(),
                512,
            )
        } > 0
    );
    worker.join().unwrap();
}

#[test]
fn search_uses_caller_suffix_order_and_continues_after_servfail() {
    for rejection in [2u8, 3] {
        let socket = udp();
        let mut state = v4_state(socket.local_addr().unwrap());
        state.dnsrch[0] = c"first.test".as_ptr().cast_mut();
        state.dnsrch[1] = c"second.test".as_ptr().cast_mut();
        let worker = thread::spawn(move || {
            let mut b = [0; 512];
            for (owner, code, marker) in [
                (b"host.first.test".as_slice(), rejection, 0),
                (b"host.second.test".as_slice(), 0, 7),
            ] {
                let (n, peer) = socket.recv_from(&mut b).unwrap();
                assert_eq!(
                    DnsMessage::decode(&b[..n]).unwrap().questions[0].qname,
                    owner
                );
                socket
                    .send_to(&answer(&b[..n], code, marker), peer)
                    .unwrap();
            }
        });
        let mut output = [0u8; 512];
        assert!(
            unsafe {
                state::search(
                    pointer(&mut state),
                    c"host".as_ptr(),
                    1,
                    1,
                    output.as_mut_ptr().cast(),
                    512,
                )
            } > 0
        );
        assert_eq!(state.res_h_errno, if rejection == 2 { 2 } else { 1 });
        worker.join().unwrap();
    }
}

#[test]
fn absolute_search_and_disabled_search_flags_use_only_bare_name() {
    for (name, clear) in [(c"host.test.", false), (c"host", true)] {
        let socket = udp();
        let mut state = v4_state(socket.local_addr().unwrap());
        state.dnsrch[0] = c"unused.test".as_ptr().cast_mut();
        if clear {
            state.options &= !(RES_DEFNAMES | RES_DNSRCH);
        }
        let expected = if clear {
            b"host".as_slice()
        } else {
            b"host.test"
        };
        let worker = thread::spawn(move || {
            let mut b = [0; 512];
            let (n, peer) = socket.recv_from(&mut b).unwrap();
            assert_eq!(
                DnsMessage::decode(&b[..n]).unwrap().questions[0].qname,
                expected
            );
            socket.send_to(&answer(&b[..n], 0, 7), peer).unwrap();
        });
        let mut output = [0u8; 512];
        assert!(
            unsafe {
                state::search(
                    pointer(&mut state),
                    name.as_ptr(),
                    1,
                    1,
                    output.as_mut_ptr().cast(),
                    512,
                )
            } > 0
        );
        worker.join().unwrap();
    }
}

#[test]
fn initialization_is_independent_and_reinitialization_close_are_repeatable() {
    let mut a = State::zeroed();
    let mut b = State::zeroed();
    for _ in 0..16 {
        assert_eq!(unsafe { state::init(pointer(&mut a)) }, 0);
        assert_eq!(unsafe { state::init(pointer(&mut b)) }, 0);
        assert_ne!(a.options & RES_INIT, 0);
        assert!((1..=3).contains(&a.nscount));
        let options = a.options;
        b.options ^= RES_TRUSTAD;
        assert_eq!(a.options, options);
        for i in 0..6 {
            if !a.dnsrch[i].is_null() && !b.dnsrch[i].is_null() {
                assert_ne!(a.dnsrch[i], b.dnsrch[i]);
                assert_eq!(unsafe { CStr::from_ptr(a.dnsrch[i]) }, unsafe {
                    CStr::from_ptr(b.dnsrch[i])
                });
            }
        }
        unsafe {
            state::close(pointer(&mut a));
            state::close(pointer(&mut a));
            state::close(pointer(&mut b));
        }
    }
}

#[test]
fn invalid_state_and_short_outputs_fail_without_writes_or_socket_io() {
    let socket = udp();
    socket.set_nonblocking(true).unwrap();
    let mut state = v4_state(socket.local_addr().unwrap());
    let query = wire();
    for capacity in 0..12 {
        let mut output = [0xa5u8; 64];
        assert_eq!(
            unsafe {
                state::send(
                    pointer(&mut state),
                    query.as_ptr().cast(),
                    query.len() as _,
                    output.as_mut_ptr().cast(),
                    capacity,
                )
            },
            -1
        );
        assert_eq!(output, [0xa5; 64]);
    }
    state.nscount = 4;
    let mut output = [0xa5u8; 64];
    assert_eq!(
        unsafe {
            state::send(
                pointer(&mut state),
                query.as_ptr().cast(),
                query.len() as _,
                output.as_mut_ptr().cast(),
                64,
            )
        },
        -1
    );
    assert_eq!(output, [0xa5; 64]);
    let mut packet = [0; 512];
    assert_eq!(
        socket.recv(&mut packet).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(unsafe { state::init(std::ptr::null_mut()) }, -1);
    unsafe {
        state::close(std::ptr::null_mut());
    }
}
