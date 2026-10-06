//! EDNS/DNSSEC request conformance through the real exported resolver entries.
use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::thread;
use std::time::Duration;

use frankenlibc_abi::resolv_state::{State, RES_INIT, RES_RECURSE, RES_DEFNAMES, RES_DNSRCH, RES_TRUSTAD};
use frankenlibc_core::resolv::dns::DnsMessage;
mod state {
    pub use frankenlibc_abi::glibc_internal_abi::{
        __res_nclose as close, __res_ninit as init, __res_nmkquery as mkquery,
        __res_nquery as query, __res_nquerydomain as querydomain,
        __res_nsearch as search, __res_nsend as send,
    };
}

fn pointer(state: &mut State) -> *mut c_void { (state as *mut State).cast() }
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
    let SocketAddr::V4(address) = address else { panic!("IPv4 fixture"); };
    let mut state = State::zeroed();
    state.options = RES_INIT | RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;
    state.retrans = 1;
    state.retry = 1;
    state.nscount = 1;
    state.nsaddr_list[0].sin_family = libc::AF_INET as _;
    state.nsaddr_list[0].sin_port = address.port().to_be();
    state.nsaddr_list[0].sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
    state.ndots_nsort = if cfg!(target_endian = "little") { 1 } else { 1 << 28 };
    state
}
fn udp() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    socket
}

// OPT construction belongs to query APIs, not the packet-only mkquery/send APIs.
fn assert_edns_query(sent: &[u8], options: u64, capacity: usize) {
    use frankenlibc_abi::resolv_state::{RES_USE_EDNS0, RES_USE_DNSSEC};
    let decoded = DnsMessage::decode(sent).unwrap();
    let enabled = options & (RES_USE_EDNS0 | RES_USE_DNSSEC) != 0;
    assert_eq!(decoded.additionals.len(), usize::from(enabled));
    assert_eq!(decoded.header.arcount, u16::from(enabled));
    if enabled {
        let opt = &decoded.additionals[0];
        assert!(opt.name.is_empty(), "OPT owner is the DNS root");
        assert_eq!(opt.rtype, 41);
        assert_eq!(opt.rclass, capacity.clamp(512, 1200) as u16);
        assert_eq!(opt.ttl, if options & RES_USE_DNSSEC != 0 { 0x8000 } else { 0 });
        assert!(opt.rdata.is_empty());
    }
    assert_eq!(sent[3] & 0x20 != 0, options & RES_TRUSTAD != 0);
}

fn answer_without_opt(sent: &[u8], code: u8, marker: u8) -> Vec<u8> {
    let mut end = 12;
    while sent[end] != 0 { end += usize::from(sent[end]) + 1; }
    end += 5; // root plus QTYPE and QCLASS
    let mut question = sent[..end].to_vec();
    question[10..12].fill(0);
    answer(&question, code, marker)
}

#[test]
fn edns_and_dnssec_emit_one_bounded_opt_without_granting_ad_trust() {
    use frankenlibc_abi::resolv_state::{RES_USE_EDNS0, RES_USE_DNSSEC};
    for options in [0, RES_USE_EDNS0, RES_USE_DNSSEC, RES_USE_EDNS0 | RES_USE_DNSSEC | RES_TRUSTAD] {
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
            let n = unsafe { state::query(pointer(&mut state), c"example.test".as_ptr(), 1, 1,
                output.as_mut_ptr().add(1).cast(), capacity as _) };
            let mut expected = worker.join().unwrap();
            if options & RES_TRUSTAD == 0 { expected[3] &= !0x20; }
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
    use frankenlibc_abi::resolv_state::{RES_USE_EDNS0, RES_USE_DNSSEC};
    for search in [false, true] {
        let socket = udp();
        let mut state = v4_state(socket.local_addr().unwrap());
        let options = RES_USE_EDNS0 | RES_USE_DNSSEC;
        state.options |= options;
        state.dnsrch[0] = c"first.test".as_ptr().cast_mut();
        state.dnsrch[1] = c"second.test".as_ptr().cast_mut();
        let worker = thread::spawn(move || {
            let queries = if search { vec![(b"host.first.test".as_slice(), 3), (b"host.second.test".as_slice(), 0)] }
                else { vec![(b"host.suffix.test".as_slice(), 0)] };
            for (owner, code) in queries {
                let mut buffer = [0u8; 512];
                let (n, peer) = socket.recv_from(&mut buffer).unwrap();
                assert_edns_query(&buffer[..n], options, 900);
                assert_eq!(DnsMessage::decode(&buffer[..n]).unwrap().questions[0].qname, owner);
                socket.send_to(&answer_without_opt(&buffer[..n], code, 82), peer).unwrap();
            }
        });
        let mut output = [0u8; 900];
        let n = unsafe {
            if search { state::search(pointer(&mut state), c"host".as_ptr(), 1, 1, output.as_mut_ptr().cast(), 900) }
            else { state::querydomain(pointer(&mut state), c"host".as_ptr(), c"suffix.test".as_ptr(), 1, 1, output.as_mut_ptr().cast(), 900) }
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
    socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
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
                    assert!(std::time::Instant::now() < deadline, "TCP fallback did not connect");
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("TCP accept: {error}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).unwrap();
        let mut tcp_query = vec![0u8; u16::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut tcp_query).unwrap();
        assert_eq!(tcp_query, sent, "fallback must not remove OPT/DO or change ID");
        let mut reply = answer_without_opt(sent, 0, 83);
        reply[7] = 2;
        // A syntactically framed opaque RRSIG; the resolver must deliver its
        // bytes, not claim it validated a signature or remove DNSSEC data.
        reply.extend_from_slice(&[0xc0, 12, 0, 46, 0, 1, 0, 0, 0, 60, 3, 32]);
        reply.extend_from_slice(&[0x5a; 800]);
        stream.write_all(&(reply.len() as u16).to_be_bytes()).unwrap();
        for fragment in reply.chunks(7) { stream.write_all(fragment).unwrap(); }
        reply
    });
    let mut output = [0xa5u8; 702];
    let n = unsafe { state::query(pointer(&mut state), c"example.test".as_ptr(), 1, 1,
        output.as_mut_ptr().add(1).cast(), 700) };
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
    use frankenlibc_abi::resolv_state::{RES_USE_EDNS0, RES_USE_DNSSEC};
    let socket = udp();
    let mut state = v4_state(socket.local_addr().unwrap());
    state.options |= RES_USE_EDNS0 | RES_USE_DNSSEC | RES_TRUSTAD;
    let mut query = [0xa5u8; 512];
    let n = unsafe { state::mkquery(pointer(&mut state), 0, c"example.test".as_ptr(), 1, 1,
        std::ptr::null(), 0, std::ptr::null(), query.as_mut_ptr().cast(), 512) };
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
    let n = unsafe { state::send(pointer(&mut state), query.as_ptr().cast(), n, output.as_mut_ptr().cast(), 512) };
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
        socket.send_to(&answer_without_opt(&buffer[..n], 1, 0), peer).unwrap();
        socket
    });
    let mut output = [0xa5u8; 512];
    let n = unsafe { state::query(pointer(&mut state), c"example.test".as_ptr(), 1, 1, output.as_mut_ptr().cast(), 512) };
    assert_eq!(n, -1);
    assert_eq!(state.res_h_errno, 3);
    assert_eq!(output[3] & 15, 1);
    assert_eq!(output[3] & 0x20, 0);
    let socket = worker.join().unwrap();
    socket.set_nonblocking(true).unwrap();
    assert_eq!(socket.recv(&mut output).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}

#[test]
fn edns_initialization_honors_res_options_without_process_wide_test_races() {
    use frankenlibc_abi::resolv_state::{RES_USE_EDNS0, RES_USE_DNSSEC};
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
        unsafe { state::close(pointer(&mut a)); state::close(pointer(&mut b)); }
        return;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "edns_initialization_honors_res_options_without_process_wide_test_races", "--nocapture"])
        .env(CHILD, "1").env("RES_OPTIONS", "edns0 timeout:1 attempts:1")
        .status().unwrap();
    assert!(status.success());
}
