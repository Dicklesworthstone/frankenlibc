#![cfg(all(target_os = "linux", target_pointer_width = "64"))]

//! Native portmapper clients against independent loopback RPC wire peers.
//! Port 111 is exclusively bound; an existing service is never replaced.

use frankenlibc_abi::rpc_abi as rpc;
use std::ffi::{c_int, c_void};
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

const SENTINEL: u64 = 0x1122_3344_5566_7788;

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|word| word.to_be_bytes()).collect()
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn address() -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 4321u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    }
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

struct Codec {
    address: *const libc::sockaddr_in,
    port: *const u64,
    expected_port: u64,
    value: u32,
    calls: u32,
    refuse: bool,
    unwind: bool,
}

unsafe extern "C-unwind" fn integer(stream: *mut c_void, data: *mut c_void) -> c_int {
    // SAFETY: every invocation supplies one live private Codec.
    let codec = unsafe { &mut *data.cast::<Codec>() };
    codec.calls += 1;
    assert_eq!(u16::from_be(unsafe { (*codec.address).sin_port }), 111);
    assert_eq!(unsafe { *codec.port }, codec.expected_port);
    assert!(!codec.unwind, "intentional application codec unwind");
    if codec.refuse {
        0
    } else {
        unsafe { rpc::xdr_u_int(stream, &mut codec.value) }
    }
}

fn remote_case(case: &str) {
    let before = fd_count();
    let peer = UdpSocket::bind("127.0.0.1:111").expect("exclusive UDP portmapper fixture");
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let no_request = matches!(case, "encode-failure" | "encode-unwind" | "invalid-timeout");
    let worker = if no_request {
        None
    } else {
        let socket = peer.try_clone().unwrap();
        let behavior = case.to_owned();
        Some(thread::spawn(move || {
            let mut request = [0u8; 256];
            let (length, client) = socket.recv_from(&mut request).unwrap();
            assert_eq!(length, 60, "{behavior}");
            assert_eq!(
                &request[4..length],
                words(&[0, 2, 100000, 2, 5, 0, 0, 0, 0, 0x2000_0001, 3, 7, 4, 37,])
            );
            if matches!(behavior.as_str(), "timeout" | "zero-timeout") {
                return;
            }
            let mut response = words(&[
                word(&request, 0),
                1,
                0,
                0,
                0,
                if behavior == "remote-error" { 3 } else { 0 },
            ]);
            if behavior != "remote-error" {
                response.extend_from_slice(&words(&[
                    if behavior == "full-port" {
                        u32::MAX
                    } else {
                        48879
                    },
                    if behavior == "advisory-length" { 0 } else { 4 },
                ]));
                if behavior != "short-results" {
                    response.extend_from_slice(&words(&[99]));
                }
            }
            socket.send_to(&response, client).unwrap();
        }))
    };
    let mut endpoint = address();
    let mut port = SENTINEL;
    let mut args = Codec {
        address: ptr::addr_of!(endpoint),
        port: ptr::addr_of!(port),
        expected_port: SENTINEL,
        value: 37,
        calls: 0,
        refuse: case == "encode-failure",
        unwind: case == "encode-unwind",
    };
    let mut result = Codec {
        address: ptr::addr_of!(endpoint),
        port: ptr::addr_of!(port),
        expected_port: if case == "full-port" {
            u32::MAX as u64
        } else {
            48879
        },
        value: 0xaaaa_aaaa,
        calls: 0,
        refuse: case == "decode-failure",
        unwind: case == "decode-unwind",
    };
    let timeout = match case {
        "zero-timeout" => rpc::Timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        "invalid-timeout" => rpc::Timeval {
            tv_sec: 0,
            tv_usec: -1,
        },
        "timeout" => rpc::Timeval {
            tv_sec: 0,
            tv_usec: 80_000,
        },
        _ => rpc::Timeval {
            tv_sec: 1,
            tv_usec: 0,
        },
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        rpc::pmap_rmtcall(
            ptr::addr_of_mut!(endpoint).cast(),
            0x2000_0001,
            3,
            7,
            integer as *const () as *mut c_void,
            ptr::addr_of_mut!(args).cast(),
            integer as *const () as *mut c_void,
            ptr::addr_of_mut!(result).cast(),
            timeout,
            &mut port,
        )
    }));
    assert_eq!(endpoint.sin_port, 0, "{case}: caller address was not reset");
    if let Some(worker) = worker {
        worker.join().unwrap();
    } else {
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.recv_from(&mut [0; 128]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "{case}: sent a request after local failure"
        );
    }
    if matches!(case, "encode-unwind" | "decode-unwind") {
        assert!(outcome.is_err(), "{case}");
    } else {
        let expected = match case {
            "encode-failure" => 1,
            "decode-failure" | "short-results" => 2,
            "remote-error" => 10,
            "timeout" | "zero-timeout" => 5,
            "invalid-timeout" => 12,
            _ => 0,
        };
        assert_eq!(outcome.unwrap(), expected, "{case}");
    }
    let decoded_port = matches!(
        case,
        "success"
            | "advisory-length"
            | "full-port"
            | "short-results"
            | "decode-failure"
            | "decode-unwind"
    );
    assert_eq!(args.calls, u32::from(case != "invalid-timeout"), "{case}");
    assert_eq!(result.calls, u32::from(decoded_port), "{case}");
    assert_eq!(
        port,
        if decoded_port {
            result.expected_port
        } else {
            SENTINEL
        },
        "{case}"
    );
    assert_eq!(
        result.value,
        if matches!(case, "success" | "advisory-length" | "full-port") {
            99
        } else {
            0xaaaa_aaaa
        },
        "{case}"
    );
    drop(peer);
    assert_eq!(fd_count(), before, "{case}: owned CLIENT/socket leaked");
}

#[repr(C)]
struct Mapping {
    program: u64,
    version: u64,
    protocol: u64,
    port: u64,
}
#[repr(C)]
struct Node {
    mapping: Mapping,
    next: *mut Node,
}

fn tcp_listener() -> TcpListener {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0);
    // SAFETY: ownership is unique and moves into TcpListener after setup.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let reuse: c_int = 1;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&reuse as *const c_int).cast(),
                std::mem::size_of_val(&reuse) as libc::socklen_t,
            )
        },
        0
    );
    let mut peer = address();
    peer.sin_port = 111u16.to_be();
    assert_eq!(
        unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&peer as *const libc::sockaddr_in).cast(),
                std::mem::size_of_val(&peer) as libc::socklen_t,
            )
        },
        0,
        "exclusive TCP portmapper fixture"
    );
    assert_eq!(unsafe { libc::listen(fd.as_raw_fd(), 8) }, 0);
    unsafe { TcpListener::from_raw_fd(fd.into_raw_fd()) }
}

fn dump_case(listener: &TcpListener, case: &str) {
    let before = fd_count();
    let server = listener.try_clone().unwrap();
    server.set_nonblocking(true).unwrap();
    let behavior = case.to_owned();
    let body = match case {
        "empty" => words(&[0]),
        "truncated" => words(&[1, 7, 8]),
        "unterminated" => words(&[1, 7, 8, 6, 5432]),
        "remote-error" => Vec::new(),
        _ => words(&[1, 7, 8, 6, 5432, 1, u32::MAX, 10, 17, u32::MAX, 0]),
    };
    let expected = body.clone();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (mut stream, _) = loop {
            match server.accept() {
                Ok(peer) => break peer,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "no DUMP request");
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("{e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut marker = [0; 4];
        stream.read_exact(&mut marker).unwrap();
        let size = u32::from_be_bytes(marker);
        assert_ne!(size & 0x8000_0000, 0);
        assert_eq!(size & 0x7fff_ffff, 40);
        let mut request = [0; 40];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request[4..], words(&[0, 2, 100000, 2, 4, 0, 0, 0, 0]));
        let mut response = words(&[
            word(&request, 0),
            1,
            0,
            0,
            0,
            if behavior == "remote-error" { 3 } else { 0 },
        ]);
        response.extend_from_slice(&body);
        if behavior == "fragmented" {
            for (index, part) in [&response[..3], &response[3..12], &response[12..]]
                .into_iter()
                .enumerate()
            {
                let final_bit = if index == 2 { 0x8000_0000 } else { 0 };
                stream
                    .write_all(&words(&[final_bit | part.len() as u32]))
                    .unwrap();
                stream.write_all(part).unwrap();
            }
        } else {
            stream
                .write_all(&words(&[0x8000_0000 | response.len() as u32]))
                .unwrap();
            stream.write_all(&response).unwrap();
        }
    });
    let mut peer = address();
    let mut head = unsafe { rpc::pmap_getmaps(ptr::addr_of_mut!(peer).cast()) }.cast::<Node>();
    worker.join().unwrap();
    assert_eq!(peer.sin_port, 0, "{case}");
    if matches!(case, "two" | "fragmented") {
        assert!(!head.is_null(), "{case}");
        let original_head = head;
        let next = unsafe { (*head).next };
        assert!(!next.is_null());
        assert!(unsafe { (*next).next.is_null() });
        let mut actual = Vec::new();
        for node in [head, next] {
            let mapping = unsafe { &(*node).mapping };
            actual.push([
                mapping.program,
                mapping.version,
                mapping.protocol,
                mapping.port,
            ]);
        }
        assert_eq!(
            actual,
            [[7, 8, 6, 5432], [u32::MAX as u64, 10, 17, u32::MAX as u64]]
        );
        let mut buffer = vec![0xa5u8; expected.len()];
        let mut xdr: rpc::Xdr = unsafe { std::mem::zeroed() };
        unsafe {
            rpc::xdrmem_create(
                ptr::addr_of_mut!(xdr).cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                0,
            );
            assert_eq!(
                rpc::xdr_pmaplist(
                    ptr::addr_of_mut!(xdr).cast(),
                    ptr::addr_of_mut!(head).cast()
                ),
                1
            );
        }
        assert_eq!(buffer, expected, "{case}: list encoding stopped early");
        assert_eq!(head, original_head);
        assert_eq!(
            unsafe { (*head).next },
            next,
            "ENCODE mutated the caller's list"
        );
        unsafe {
            rpc::xdr_free(
                rpc::xdr_pmaplist as *const () as *mut c_void,
                ptr::addr_of_mut!(head).cast(),
            );
        }
        assert!(head.is_null(), "XDR_FREE did not reset the list head");
    } else {
        assert!(head.is_null(), "{case}: partial/untrusted list escaped");
    }
    assert_eq!(fd_count(), before, "{case}: owned CLIENT/socket leaked");
}

#[test]
#[ignore = "requires exclusive permission to bind loopback TCP/UDP port 111"]
fn portmapper_dump_and_callit_use_actual_abi() {
    for case in [
        "success",
        "advisory-length",
        "full-port",
        "short-results",
        "decode-failure",
        "encode-failure",
        "remote-error",
        "timeout",
        "zero-timeout",
        "invalid-timeout",
        "encode-unwind",
        "decode-unwind",
    ] {
        remote_case(case);
    }
    let before = fd_count();
    let listener = tcp_listener();
    for case in [
        "two",
        "fragmented",
        "empty",
        "truncated",
        "unterminated",
        "remote-error",
    ] {
        dump_case(&listener, case);
    }
    drop(listener);
    assert_eq!(fd_count(), before);
    println!("NATIVE PORTMAPPER: 18 wire, callback, ownership and unwind cases passed");
}

#[test]
fn xdr_unsigned_long_decode_preserves_all_32_wire_bits() {
    for value in [0u32, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
        let mut bytes = value.to_be_bytes();
        for length in [3, 4] {
            let mut output = [SENTINEL; 3];
            let mut xdr: rpc::Xdr = unsafe { std::mem::zeroed() };
            unsafe {
                rpc::xdrmem_create(
                    ptr::addr_of_mut!(xdr).cast(),
                    bytes.as_mut_ptr().cast(),
                    length,
                    1,
                );
                assert_eq!(
                    rpc::xdr_u_long(ptr::addr_of_mut!(xdr).cast(), &mut output[1]),
                    c_int::from(length == 4)
                );
            }
            assert_eq!(
                output,
                [
                    SENTINEL,
                    if length == 4 {
                        u64::from(value)
                    } else {
                        SENTINEL
                    },
                    SENTINEL
                ]
            );
        }
    }
}
