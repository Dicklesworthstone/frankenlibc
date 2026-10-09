//! Exercise the deployed global entry bodies, not only the state delegates.
use frankenlibc_abi::glibc_internal_abi::{__res_mkquery, __res_nclose, __res_send, __res_state};
use frankenlibc_abi::resolv_state::{
    RES_DEFNAMES, RES_DNSRCH, RES_INIT, RES_RECURSE, RES_TRUSTAD, State,
};
use frankenlibc_abi::unistd_abi::{res_query, res_search};
use frankenlibc_core::resolv::dns::DnsMessage;
use std::ffi::c_void;
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

struct Cleanup(*mut c_void);
impl Drop for Cleanup {
    fn drop(&mut self) {
        // SAFETY: the test's TLS state remains valid and exclusively accessed.
        unsafe { __res_nclose(self.0) };
    }
}
fn configure(address: SocketAddr) -> Cleanup {
    let SocketAddr::V4(address) = address else {
        panic!("IPv4 test endpoint")
    };
    // SAFETY: __res_state exposes this thread's aligned state. Each test runs
    // on its own thread; no reference is retained across a resolver operation.
    unsafe {
        let pointer = __res_state();
        __res_nclose(pointer);
        let state = &mut *pointer.cast::<State>();
        *state = State::zeroed();
        state.options = RES_INIT | RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;
        state.retrans = 1;
        state.retry = 1;
        state.ndots_nsort = 1;
        state.nscount = 1;
        state.nsaddr_list[0].sin_family = libc::AF_INET as _;
        state.nsaddr_list[0].sin_port = address.port().to_be();
        state.nsaddr_list[0].sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
        Cleanup(pointer)
    }
}
fn udp() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
}
fn reply(query: &[u8], code: u8, marker: u8) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] |= 0x80;
    response[3] = 0xa0 | code;
    if code == 0 {
        response[7] = 1;
        response.extend_from_slice(&[
            0xc0, 12, 0, 16, 0, 3, 0, 0, 0, 60, 0, 4, 3, b'o', b'k', marker,
        ]);
    }
    response
}
#[test]
fn global_builder_observes_public_flags_class_and_notify() {
    let socket = udp();
    let cleanup = configure(socket.local_addr().unwrap());
    for (options, flags) in [(RES_INIT, 0), (RES_INIT | RES_RECURSE | RES_TRUSTAD, 0x120)] {
        let mut output = [0xa5u8; 512];
        // SAFETY: caller-owned TLS state and valid C input/output spans.
        let n = unsafe {
            (*cleanup.0.cast::<State>()).options = options;
            __res_mkquery(
                0,
                c"example.test".as_ptr(),
                3,
                16,
                std::ptr::null(),
                0,
                std::ptr::null(),
                output.as_mut_ptr().cast(),
                512,
            )
        };
        assert_eq!(n, 30);
        assert_eq!(u16::from_be_bytes([output[2], output[3]]), flags);
        assert_eq!(&output[26..30], &[0, 16, 0, 3]);
        assert_eq!(output[30], 0xa5);
    }
    let mut output = [0u8; 512];
    let n = unsafe {
        __res_mkquery(
            4,
            c"example.test".as_ptr(),
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
    let message = DnsMessage::decode(&output[..n as usize]).unwrap();
    assert_eq!(message.additionals[0].name, b"edge.test");
}
#[test]
fn global_query_uses_mutated_endpoint_and_non_in_class() {
    for marker in [11, 22] {
        let socket = udp();
        let _cleanup = configure(socket.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let mut request = [0u8; 512];
            let (n, peer) = socket.recv_from(&mut request).unwrap();
            let message = DnsMessage::decode(&request[..n]).unwrap();
            assert_eq!(message.questions[0].qclass, 3);
            assert_eq!(message.questions[0].qtype, 16);
            socket
                .send_to(&reply(&request[..n], 0, marker), peer)
                .unwrap();
        });
        let mut output = [0xa5u8; 512];
        let n = unsafe { res_query(c"example.test".as_ptr(), 3, 16, output.as_mut_ptr(), 512) };
        assert_eq!(n, 46);
        assert_eq!(output[n as usize - 1], marker);
        assert_eq!(output[3] & 0x20, 0);
        assert_eq!(output[n as usize], 0xa5);
        worker.join().unwrap();
    }
}
#[test]
fn global_negative_answer_is_copied_and_error_slots_agree() {
    let socket = udp();
    let cleanup = configure(socket.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let (n, peer) = socket.recv_from(&mut request).unwrap();
        socket.send_to(&reply(&request[..n], 3, 0), peer).unwrap();
    });
    let mut output = [0xa5u8; 512];
    assert_eq!(
        unsafe { res_query(c"missing.test".as_ptr(), 3, 16, output.as_mut_ptr(), 512) },
        -1
    );
    assert_ne!(output[2] & 0x80, 0);
    assert_eq!(output[3] & 15, 3);
    assert_eq!(unsafe { (*cleanup.0.cast::<State>()).res_h_errno }, 1);
    assert_eq!(
        unsafe { *frankenlibc_abi::resolv_abi::__h_errno_location() },
        1
    );
    worker.join().unwrap();
}
#[test]
fn global_search_uses_caller_suffixes_instead_of_cached_configuration() {
    let socket = udp();
    let cleanup = configure(socket.local_addr().unwrap());
    unsafe {
        (*cleanup.0.cast::<State>()).dnsrch[0] = c"first.test".as_ptr().cast_mut();
        (*cleanup.0.cast::<State>()).dnsrch[1] = c"second.test".as_ptr().cast_mut();
    }
    let worker = thread::spawn(move || {
        for (owner, code) in [
            (b"host.first.test".as_slice(), 3),
            (b"host.second.test".as_slice(), 0),
        ] {
            let mut request = [0u8; 512];
            let (n, peer) = socket.recv_from(&mut request).unwrap();
            assert_eq!(
                DnsMessage::decode(&request[..n]).unwrap().questions[0].qname,
                owner
            );
            socket
                .send_to(&reply(&request[..n], code, 7), peer)
                .unwrap();
        }
    });
    let mut output = [0u8; 512];
    assert!(unsafe { res_search(c"host".as_ptr(), 3, 16, output.as_mut_ptr(), 512) } > 0);
    worker.join().unwrap();
}
#[test]
fn global_raw_send_rejects_invalid_output_before_socket_activity() {
    let socket = udp();
    socket.set_nonblocking(true).unwrap();
    let _cleanup = configure(socket.local_addr().unwrap());
    let message = [0x31u8, 0x29, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    for capacity in 0..12 {
        let mut output = [0xa5u8; 64];
        assert_eq!(
            unsafe {
                __res_send(
                    message.as_ptr().cast(),
                    17,
                    output.as_mut_ptr().cast(),
                    capacity,
                )
            },
            -1
        );
        assert_eq!(output, [0xa5; 64]);
    }
    assert_eq!(
        socket.recv(&mut [0u8; 512]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
#[test]
fn global_tls_addresses_are_distinct_and_stable_across_threads() {
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let barrier = barrier.clone();
            thread::spawn(move || {
                let address = unsafe { __res_state() } as usize;
                barrier.wait();
                barrier.wait();
                assert_eq!(unsafe { __res_state() } as usize, address);
                address
            })
        })
        .collect();
    barrier.wait();
    barrier.wait();
    let addresses: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_ne!(addresses[0], addresses[1]);
    assert!(!addresses.contains(&(unsafe { __res_state() } as usize)));
}
