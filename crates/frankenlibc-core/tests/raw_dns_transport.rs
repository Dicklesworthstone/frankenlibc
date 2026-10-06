//! Real loopback sockets exercise the transport used by the raw resolver ABI.
//! No public DNS, host resolver, or candidate/host symbol interposition is used.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use frankenlibc_core::dns_transport::{QueryError, exchange as address_exchange, raw};
use frankenlibc_core::resolv::dns::{DnsMessage, qtype, rcode};

const TIMEOUT: Duration = Duration::from_secs(3);

fn query() -> Vec<u8> {
    let mut wire = vec![0; 512];
    let length = DnsMessage::new_query(0x3210, b"test.invalid", qtype::A)
        .unwrap()
        .encode(&mut wire)
        .unwrap();
    wire.truncate(length);
    wire
}

fn answer(sent: &[u8]) -> Vec<u8> {
    let mut wire = sent.to_vec();
    wire[2] = 0x81 | (sent[2] & 0x78);
    wire[3] = 0x80;
    wire[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
    wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
    wire
}

fn udp() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    socket.set_write_timeout(Some(TIMEOUT)).unwrap();
    socket
}

fn receive(socket: &UdpSocket) -> (Vec<u8>, std::net::SocketAddr) {
    let mut buffer = [0; 4096];
    let (length, peer) = socket.recv_from(&mut buffer).unwrap();
    (buffer[..length].to_vec(), peer)
}

fn accept(listener: &TcpListener) -> TcpStream {
    // Bound accept as well as reads: a missing TCP fallback must fail a test,
    // not leave its server thread hanging indefinitely.
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_read_timeout(Some(TIMEOUT)).unwrap();
                stream.set_write_timeout(Some(TIMEOUT)).unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "no TCP fallback connection");
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}

fn read_tcp_query(stream: &mut TcpStream) -> Vec<u8> {
    let mut length = [0; 2];
    stream.read_exact(&mut length).unwrap();
    let mut packet = vec![0; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut packet).unwrap();
    packet
}

#[test]
fn udp_rejects_forged_peer_id_opcode_name_type_class_and_label_identity() {
    let socket = udp();
    let address = socket.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (sent, peer) = receive(&socket);
        let good = answer(&sent);
        // Correct ID and question from the wrong UDP source must not win.
        let mut rogue_reply = good.clone();
        *rogue_reply.last_mut().unwrap() = 99;
        udp().send_to(&rogue_reply, peer).unwrap();
        for (position, mask) in [
            (0, 1),                 // transaction ID
            (2, 8),                 // opcode
            (13, 1),                // question name
            (sent.len() - 3, 1),    // QTYPE
            (sent.len() - 1, 1),    // QCLASS
            (5, 1),                 // question count
        ] {
            let mut forged = rogue_reply.clone();
            forged[position] ^= mask;
            socket.send_to(&forged, peer).unwrap();
        }
        // One label containing a literal dot is not two labels.
        let mut literal_dot = sent[..12].to_vec();
        literal_dot.extend_from_slice(b"\x0ctest.invalid\x00\x00\x01\x00\x01");
        socket.send_to(&answer(&literal_dot), peer).unwrap();
        let mut uppercase = good;
        uppercase[13..17].make_ascii_uppercase();
        socket.send_to(&uppercase, peer).unwrap();
        uppercase
    });
    let result = raw::exchange(address, &query(), TIMEOUT, false, false).unwrap();
    assert_eq!(result.transport, raw::Transport::Udp);
    assert_eq!(result.packet, worker.join().unwrap());
}

#[test]
fn udp_truncation_falls_back_to_fragmented_tcp_and_retains_wire_length() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let socket = UdpSocket::bind(address).unwrap();
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    let worker = thread::spawn(move || {
        let (sent, peer) = receive(&socket);
        let mut truncated = answer(&sent);
        truncated[2] |= 2;
        truncated.truncate(sent.len() + 1); // Incomplete RR is valid for TC fallback.
        socket.send_to(&truncated, peer).unwrap();
        let mut stream = accept(&listener);
        assert_eq!(read_tcp_query(&mut stream), sent);
        let good = answer(&sent);
        let prefix = (good.len() as u16).to_be_bytes();
        stream.write_all(&prefix[..1]).unwrap();
        stream.write_all(&prefix[1..]).unwrap();
        for chunk in good.chunks(3) {
            stream.write_all(chunk).unwrap();
        }
        good
    });
    let result = raw::exchange(address, &query(), TIMEOUT, false, false).unwrap();
    assert_eq!(result.transport, raw::Transport::Tcp);
    assert_eq!(result.packet, worker.join().unwrap());
    let mut out = [0xa5; 14];
    let reported = result.copy_answer(&mut out[1..13]).unwrap();
    assert_eq!(reported, result.packet.len());
    assert!(reported > 12);
    assert_eq!(out[3] & 2, 2);
    assert_eq!(out[0], 0xa5);
    assert_eq!(out[13], 0xa5);
}

#[test]
fn ignore_truncation_returns_the_validated_udp_packet_without_tcp() {
    let socket = udp();
    let address = socket.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (sent, peer) = receive(&socket);
        let mut truncated = sent;
        truncated[2] |= 0x82;
        socket.send_to(&truncated, peer).unwrap();
        truncated
    });
    let result = raw::exchange(address, &query(), TIMEOUT, false, true).unwrap();
    assert_eq!(result.transport, raw::Transport::Udp);
    assert_eq!(result.packet, worker.join().unwrap());
}

#[test]
fn forced_tcp_ignores_wrong_question_frames_before_accepting_the_right_one() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let mut stream = accept(&listener);
        let sent = read_tcp_query(&mut stream);
        let good = answer(&sent);
        let mut wrong = good.clone();
        wrong[sent.len() - 3] ^= 1;
        *wrong.last_mut().unwrap() = 99;
        for frame in [&wrong, &good] {
            stream.write_all(&(frame.len() as u16).to_be_bytes()).unwrap();
            stream.write_all(frame).unwrap();
        }
        good
    });
    let result = raw::exchange(address, &query(), TIMEOUT, true, false).unwrap();
    assert_eq!(result.transport, raw::Transport::Tcp);
    assert_eq!(result.packet, worker.join().unwrap());
}

#[test]
fn valid_non_address_question_type_and_class_are_not_rewritten() {
    let socket = udp();
    let address = socket.local_addr().unwrap();
    let mut sent = query();
    let length = sent.len();
    sent[length - 4..].copy_from_slice(&[0, 16, 0, 3]); // TXT, CHAOS.
    let expected = sent.clone();
    let worker = thread::spawn(move || {
        let (mut packet, peer) = receive(&socket);
        assert_eq!(packet, expected);
        packet[2] |= 0x80;
        socket.send_to(&packet, peer).unwrap();
        packet
    });
    let result = raw::exchange(address, &sent, TIMEOUT, false, false).unwrap();
    assert_eq!(result.packet, worker.join().unwrap());
}

#[test]
fn raw_notify_is_opcode_bound_without_widening_the_address_lookup_api() {
    let socket = udp();
    let address = socket.local_addr().unwrap();
    let mut sent = query();
    sent[2] |= 4 << 3;
    assert!(matches!(
        address_exchange(address, &sent, TIMEOUT, false),
        Err(QueryError::InvalidQuery)
    ));
    let worker = thread::spawn(move || {
        let (packet, peer) = receive(&socket);
        let good = answer(&packet);
        let mut wrong = good.clone();
        wrong[2] &= !0x78; // Matching question, but QUERY instead of NOTIFY.
        socket.send_to(&wrong, peer).unwrap();
        socket.send_to(&good, peer).unwrap();
        good
    });
    let result = raw::exchange(address, &sent, TIMEOUT, false, false).unwrap();
    assert_eq!(result.packet, worker.join().unwrap());
}

#[test]
fn raw_send_fails_over_on_dns_refusal_and_keeps_the_negative_wire_answer() {
    let primary = udp();
    let secondary = udp();
    let config = raw::Config {
        nameservers: vec![primary.local_addr().unwrap(), secondary.local_addr().unwrap()],
        timeout: TIMEOUT,
        attempts: 1,
        rotate: false,
        use_vc: false,
        ignore_truncation: false,
        trust_ad: false,
    };
    let first = thread::spawn(move || {
        let (mut packet, peer) = receive(&primary);
        packet[2] |= 0x80;
        packet[3] = 0x80 | rcode::REFUSED;
        primary.send_to(&packet, peer).unwrap();
    });
    let second = thread::spawn(move || {
        let (mut packet, peer) = receive(&secondary);
        packet[2] |= 0x80;
        packet[3] = 0xa0 | rcode::NXDOMAIN; // Untrusted AD must be cleared.
        secondary.send_to(&packet, peer).unwrap();
        packet[3] &= !0x20;
        packet
    });
    let result = raw::send(&query(), &config).unwrap();
    assert_eq!(result.packet, second.join().unwrap());
    first.join().unwrap();
}

#[test]
fn ignored_packets_cannot_extend_the_original_deadline() {
    let socket = udp();
    let address = socket.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (sent, peer) = receive(&socket);
        let mut wrong = answer(&sent);
        wrong[0] ^= 1;
        for _ in 0..100 {
            let _ = socket.send_to(&wrong, peer);
            thread::sleep(Duration::from_millis(2));
        }
    });
    let start = Instant::now();
    let result = raw::exchange(address, &query(), Duration::from_millis(50), false, false);
    assert!(matches!(result, Err(QueryError::Io(error))
        if error.kind() == std::io::ErrorKind::TimedOut));
    assert!(start.elapsed() < Duration::from_secs(2));
    worker.join().unwrap();
}
