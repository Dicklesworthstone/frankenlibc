#![cfg(all(target_os = "linux", target_pointer_width = "64"))]
//! Actual production ABI tests. Loopback peers construct independent wire words;
//! they do not share the production encoder/decoder. Each mode/case gets a fresh
//! process, so the adaptive policy's history cannot make another case pass/fail.

use frankenlibc_abi::rpc_abi as rpc;
use std::ffi::{c_char, c_int, c_void};
use std::mem::{offset_of, size_of};
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

const CHILD: &str = "FRANKENLIBC_RPC_UDP_CASE";
type XdrProc = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
#[repr(C)]
struct Auth {
    credential: OpaqueAuth,
    verifier: OpaqueAuth,
    key: [u8; 8],
    ops: *const AuthOps,
    private: *mut c_void,
}
#[repr(C)]
struct OpaqueAuth {
    flavor: c_int,
    base: *mut c_char,
    length: u32,
}
#[repr(C)]
struct AuthOps {
    next: unsafe extern "C" fn(*mut Auth),
    marshal: unsafe extern "C" fn(*mut Auth, *mut c_void) -> c_int,
    validate: unsafe extern "C" fn(*mut Auth, *mut OpaqueAuth) -> c_int,
    refresh: unsafe extern "C" fn(*mut Auth) -> c_int,
    destroy: unsafe extern "C" fn(*mut Auth),
}
#[repr(C)]
struct Client {
    auth: *mut Auth,
    ops: *const ClientOps,
    private: *mut c_void,
}
#[repr(C)]
struct ClientOps {
    call: unsafe extern "C" fn(
        *mut Client,
        u64,
        Option<XdrProc>,
        *mut c_void,
        Option<XdrProc>,
        *mut c_void,
        rpc::Timeval,
    ) -> c_int,
    abort: unsafe extern "C" fn(),
    error: unsafe extern "C" fn(*mut Client, *mut RpcError),
    free: unsafe extern "C" fn(*mut Client, Option<XdrProc>, *mut c_void) -> c_int,
    destroy: unsafe extern "C" fn(*mut Client),
    control: unsafe extern "C" fn(*mut Client, c_int, *mut c_char) -> c_int,
}
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct RpcError {
    status: c_int,
    padding: u32,
    detail: [u8; 16],
}
struct Handle(*mut Client);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { ((*(*self.0).ops).destroy)(self.0) };
    }
}

fn interval(micros: i64) -> rpc::Timeval {
    rpc::Timeval {
        tv_sec: micros / 1_000_000,
        tv_usec: micros % 1_000_000,
    }
}
unsafe extern "C" fn integer(xdr: *mut c_void, value: *mut c_void) -> c_int {
    unsafe { rpc::xdr_u_int(xdr, value.cast()) }
}
unsafe extern "C" fn refuse(_: *mut c_void, _: *mut c_void) -> c_int {
    0
}
unsafe extern "C" fn free_probe(xdr: *mut c_void, value: *mut c_void) -> c_int {
    unsafe {
        value.cast::<c_int>().write(xdr.cast::<c_int>().read());
    }
    1
}

fn endpoint(server: &UdpSocket) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: server.local_addr().unwrap().port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    }
}
fn server() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}
fn create(peer: &mut libc::sockaddr_in, fd: &mut c_int, receive: u32) -> Handle {
    let pointer = unsafe {
        rpc::clntudp_bufcreate(
            (peer as *mut libc::sockaddr_in).cast(),
            0x2000_0042,
            7,
            interval(20_000),
            fd,
            256,
            receive,
        )
    };
    assert!(
        !pointer.is_null(),
        "native UDP constructor still returned a null handle"
    );
    Handle(pointer.cast())
}
fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|word| word.to_be_bytes()).collect()
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn success(request: &[u8], result: u32) -> Vec<u8> {
    words(&[word(request, 0), 1, 0, 0, 0, 0, result])
}
fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}
fn error(client: &Handle) -> RpcError {
    let mut result = RpcError {
        status: -1,
        padding: 0,
        detail: [0; 16],
    };
    unsafe { ((*(*client.0).ops).error)(client.0, &mut result) };
    result
}
fn control<T>(client: &Handle, request: c_int, value: &mut T) -> c_int {
    unsafe { ((*(*client.0).ops).control)(client.0, request, (value as *mut T).cast()) }
}
fn invoke(client: &Handle, input: &mut u32, output: &mut u32, timeout: i64) -> c_int {
    unsafe {
        ((*(*client.0).ops).call)(
            client.0,
            3,
            Some(integer),
            (input as *mut u32).cast(),
            Some(integer),
            (output as *mut u32).cast(),
            interval(timeout),
        )
    }
}

#[repr(C)]
struct Reentrant {
    client: *mut Client,
    input: u32,
}
unsafe extern "C" fn reenter(xdr: *mut c_void, argument: *mut c_void) -> c_int {
    let state = unsafe { &mut *argument.cast::<Reentrant>() };
    let mut timeout = interval(5_000);
    assert_eq!(
        unsafe {
            ((*(*state.client).ops).control)(
                state.client,
                1,
                (&mut timeout as *mut rpc::Timeval).cast(),
            )
        },
        0
    );
    let mut error = RpcError {
        status: 0,
        padding: 0,
        detail: [0; 16],
    };
    unsafe { ((*(*state.client).ops).error)(state.client, &mut error) };
    assert_eq!(error.status, 12);
    assert_eq!(
        c_int::from_ne_bytes(error.detail[..4].try_into().unwrap()),
        libc::EBUSY
    );
    unsafe { ((*(*state.client).ops).destroy)(state.client) };
    unsafe { rpc::xdr_u_int(xdr, &mut state.input) }
}

#[test]
fn rpc_udp_case() {
    let Ok(case) = std::env::var(CHILD) else {
        return;
    };
    assert_eq!(
        (
            size_of::<Client>(),
            size_of::<ClientOps>(),
            size_of::<Auth>(),
            size_of::<RpcError>()
        ),
        (24, 48, 72, 24)
    );
    assert_eq!(
        (offset_of!(Auth, ops), offset_of!(RpcError, detail)),
        (56, 8)
    );

    if case == "authnone" {
        let auth = unsafe { rpc::authnone_create() }.cast::<Auth>();
        assert!(!auth.is_null());
        assert_eq!(auth, unsafe { rpc::authnone_create() }.cast());
        unsafe {
            assert_eq!(
                ((*auth).credential.flavor, (*auth).credential.length),
                (0, 0)
            );
            ((*(*auth).ops).next)(auth);
            assert_eq!(((*(*auth).ops).refresh)(auth), 0);
            ((*(*auth).ops).destroy)(auth);
        }
        assert_eq!(auth, unsafe { rpc::authnone_create() }.cast());
        return;
    }
    let socket = server();
    let mut peer = endpoint(&socket);
    if case == "invalid-constructor" {
        let mut fd = -1;
        for retry in [
            interval(0),
            interval(-1),
            rpc::Timeval {
                tv_sec: 0,
                tv_usec: 1_000_000,
            },
        ] {
            assert!(
                unsafe {
                    rpc::clntudp_create(
                        (&mut peer as *mut libc::sockaddr_in).cast(),
                        1,
                        1,
                        retry,
                        &mut fd,
                    )
                }
                .is_null()
            );
            assert_eq!(fd, -1);
        }
        assert!(
            unsafe { rpc::clntudp_create(ptr::null_mut(), 1, 1, interval(1000), &mut fd) }
                .is_null()
        );
        let state = unsafe { rpc::__rpc_thread_createerr() }.cast::<u8>();
        assert_eq!(unsafe { state.cast::<c_int>().read() }, 12);
        assert_eq!(unsafe { state.add(8).cast::<c_int>().read() }, 12);
        assert_eq!(
            unsafe { state.add(16).cast::<c_int>().read() },
            libc::EFAULT
        );
        return;
    }
    if case == "publication-failure" {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let page = unsafe {
            libc::mmap(
                ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        unsafe { page.cast::<c_int>().write(-1) };
        assert_eq!(
            unsafe { libc::mprotect(page, page_size, libc::PROT_READ) },
            0
        );
        let before = fd_count();
        let result = unsafe {
            rpc::clntudp_create(
                (&mut peer as *mut libc::sockaddr_in).cast(),
                1,
                1,
                interval(1000),
                page.cast(),
            )
        };
        assert!(result.is_null());
        assert_eq!(
            fd_count(),
            before,
            "failed constructor publication leaked a descriptor"
        );
        unsafe { libc::munmap(page, page_size) };
        return;
    }
    let borrowed = if case == "borrowed" {
        Some(server())
    } else {
        None
    };
    let mut fd = borrowed.as_ref().map_or(-1, AsRawFd::as_raw_fd);
    let flags = if fd >= 0 {
        unsafe { libc::fcntl(fd, libc::F_GETFL) }
    } else {
        0
    };
    let mut client = Some(create(
        &mut peer,
        &mut fd,
        if case == "truncated" { 24 } else { 256 },
    ));
    let handle = client.as_ref().unwrap();
    if case == "owned" || case == "borrowed" || case == "fd-nclose" {
        let mut observed = -1;
        assert_eq!(control(handle, 6, &mut observed), 1);
        assert_eq!(observed, fd);
        if case == "fd-nclose" {
            assert_eq!(control(handle, 9, &mut observed), 1);
        }
        drop(client.take());
        if case == "owned" {
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        } else {
            assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
        }
        if case == "borrowed" {
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
        }
        if case == "fd-nclose" {
            unsafe { libc::close(fd) };
        }
        return;
    }
    if case == "freeres" {
        let mut operation = -1;
        assert_eq!(
            unsafe {
                ((*(*handle.0).ops).free)(
                    handle.0,
                    Some(free_probe),
                    (&mut operation as *mut c_int).cast(),
                )
            },
            1
        );
        assert_eq!(operation, 2);
        unsafe { ((*(*handle.0).ops).abort)() };
        return;
    }
    if case == "encode-failure" {
        let mut value = 0u32;
        assert_eq!(
            unsafe {
                ((*(*handle.0).ops).call)(
                    handle.0,
                    3,
                    Some(refuse),
                    ptr::null_mut(),
                    Some(integer),
                    (&mut value as *mut u32).cast(),
                    interval(50_000),
                )
            },
            1
        );
        socket.set_nonblocking(true).unwrap();
        assert_eq!(
            socket.recv_from(&mut [0; 128]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        return;
    }
    if case == "controls" {
        for (request, expected) in [(12, 7u64), (14, 0x2000_0042u64)] {
            let mut storage = [0xa5u8; 16];
            assert_eq!(control(handle, request, &mut storage), 1);
            assert_eq!(
                u64::from_ne_bytes(storage[..8].try_into().unwrap()),
                expected
            );
            assert_eq!(&storage[8..], &[0xa5; 8]);
        }
        let mut program = 0x2000_0043u64;
        let mut version = 8u64;
        let mut xid = 0xdead_beefu64;
        assert_eq!(control(handle, 15, &mut program), 1);
        assert_eq!(control(handle, 13, &mut version), 1);
        assert_eq!(control(handle, 11, &mut xid), 1);
        let mut default = interval(0);
        assert_eq!(control(handle, 2, &mut default), 1);
        assert_eq!((default.tv_sec, default.tv_usec), (-1, -1));
    }
    if case == "timeout-override" {
        let mut timeout = interval(40_000);
        assert_eq!(control(handle, 1, &mut timeout), 1);
        let mut output = 0;
        let start = Instant::now();
        assert_eq!(invoke(handle, &mut 41, &mut output, 1_000_000), 5);
        assert!(start.elapsed() < Duration::from_millis(500));
        return;
    }
    if case == "zero-timeout" {
        assert_eq!(invoke(handle, &mut 41, &mut 0, 0), 5);
        let mut request = [0; 256];
        let (length, _) = socket.recv_from(&mut request).unwrap();
        assert_eq!(
            length, 44,
            "zero timeout must send once without waiting for a result"
        );
        return;
    }
    let behavior = case.clone();
    let peer_thread = thread::spawn(move || {
        let mut request = [0u8; 1024];
        let (length, client) = socket.recv_from(&mut request).unwrap();
        assert_eq!(length, 44);
        assert_eq!(
            (word(&request, 4), word(&request, 8), word(&request, 20)),
            (0, 2, 3)
        );
        assert_eq!(&request[24..40], &[0u8; 16]);
        assert_eq!(word(&request, 40), 41);
        if behavior == "controls" {
            assert_eq!(
                (word(&request, 0), word(&request, 12), word(&request, 16)),
                (0xdead_beef, 0x2000_0043, 8)
            );
        } else {
            assert_eq!((word(&request, 12), word(&request, 16)), (0x2000_0042, 7));
        }
        if behavior == "retry" {
            let mut second = [0u8; 1024];
            let (again, from) = socket.recv_from(&mut second).unwrap();
            assert_eq!((again, from), (length, client));
            assert_eq!(
                &second[..again],
                &request[..length],
                "retransmission changed the request/XID"
            );
        }
        if behavior == "filter" || behavior == "deadline" {
            let other = server();
            other.send_to(&success(&request, 999), client).unwrap();
            let mut unrelated = success(&request, 888);
            unrelated[..4].copy_from_slice(&word(&request, 0).wrapping_add(1).to_be_bytes());
            socket.send_to(&unrelated, client).unwrap();
            if behavior == "deadline" {
                let end = Instant::now() + Duration::from_millis(250);
                while Instant::now() < end {
                    let _ = socket.send_to(&unrelated, client);
                    thread::sleep(Duration::from_millis(1));
                }
                return;
            }
        }
        let xid = word(&request, 0);
        let response = match behavior.as_str() {
            "program-version" => words(&[xid, 1, 0, 0, 0, 2, 3, 9]),
            "rpc-version" => words(&[xid, 1, 1, 0, 2, 2]),
            "auth-denied" => words(&[xid, 1, 1, 1, 5]),
            "procedure-unavailable" => words(&[xid, 1, 0, 0, 0, 3]),
            "malformed" => words(&[xid, 1, 9]),
            "truncated" => {
                let mut bytes = success(&request, 42);
                bytes.resize(160, 0);
                bytes
            }
            _ => success(&request, 42),
        };
        socket.send_to(&response, client).unwrap();
    });
    let mut result = 0u32;
    let start = Instant::now();
    let status = if case == "reentrant" {
        let mut context = Reentrant {
            client: handle.0,
            input: 41,
        };
        unsafe {
            ((*(*handle.0).ops).call)(
                handle.0,
                3,
                Some(reenter),
                (&mut context as *mut Reentrant).cast(),
                Some(integer),
                (&mut result as *mut u32).cast(),
                interval(1_000_000),
            )
        }
    } else if case == "decode-failure" {
        let mut input = 41u32;
        unsafe {
            ((*(*handle.0).ops).call)(
                handle.0,
                3,
                Some(integer),
                (&mut input as *mut u32).cast(),
                Some(refuse),
                (&mut result as *mut u32).cast(),
                interval(1_000_000),
            )
        }
    } else {
        invoke(
            handle,
            &mut 41,
            &mut result,
            if case == "deadline" {
                40_000
            } else {
                1_000_000
            },
        )
    };
    let elapsed = start.elapsed();
    let expected = match case.as_str() {
        "program-version" => 9,
        "rpc-version" => 6,
        "auth-denied" => 7,
        "procedure-unavailable" => 10,
        "malformed" | "truncated" | "decode-failure" => 2,
        "deadline" => 5,
        _ => 0,
    };
    assert_eq!(status, expected, "{case}");
    let observed = error(handle);
    assert_eq!(observed.status, status);
    if status == 0 {
        assert_eq!(result, 42);
    } else {
        assert_eq!(result, 0);
    }
    if case == "program-version" || case == "rpc-version" {
        let versions = (
            u64::from_ne_bytes(observed.detail[..8].try_into().unwrap()),
            u64::from_ne_bytes(observed.detail[8..].try_into().unwrap()),
        );
        assert_eq!(
            versions,
            if case == "rpc-version" {
                (2, 2)
            } else {
                (3, 9)
            }
        );
    }
    if case == "auth-denied" {
        assert_eq!(
            u32::from_ne_bytes(observed.detail[..4].try_into().unwrap()),
            5
        );
    }
    if case == "deadline" {
        assert!(
            elapsed < Duration::from_millis(200),
            "unrelated replies extended the deadline: {elapsed:?}"
        );
    }
    peer_thread.join().unwrap();
}

#[test]
fn native_udp_clients_are_process_isolated() {
    let cases = [
        "authnone",
        "invalid-constructor",
        "publication-failure",
        "owned",
        "borrowed",
        "fd-nclose",
        "freeres",
        "encode-failure",
        "decode-failure",
        "controls",
        "timeout-override",
        "zero-timeout",
        "success",
        "retry",
        "filter",
        "deadline",
        "program-version",
        "rpc-version",
        "auth-denied",
        "procedure-unavailable",
        "malformed",
        "truncated",
        "reentrant",
    ];
    for mode in ["strict", "hardened"] {
        for case in cases {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "rpc_udp_case", "--nocapture"])
                .env("FRANKENLIBC_MODE", mode)
                .env("FRANKENLIBC_RUNTIME_MATH", "off")
                .env(CHILD, case)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode}/{case}: {:?}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    println!(
        "NATIVE UDP RPC: {} isolated ABI cases passed",
        cases.len() * 2
    );
}

#[test]
#[ignore = "requires exclusive permission to bind loopback UDP port 111"]
fn portmapper_discovery_and_registration_use_actual_abi() {
    let portmapper =
        UdpSocket::bind("127.0.0.1:111").expect("exclusive loopback portmapper fixture");
    portmapper
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let service = server();
    let service_port = service.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        for (index, procedure) in [3, 3, 1, 2, 3, 3].into_iter().enumerate() {
            let mut request = [0u8; 128];
            let (length, client) = portmapper.recv_from(&mut request).unwrap();
            assert_eq!(length, 56);
            assert_eq!(
                (word(&request, 12), word(&request, 16), word(&request, 20)),
                (100000, 2, procedure)
            );
            assert_eq!((word(&request, 40), word(&request, 44)), (0x2000_0042, 7));
            let reply = if index == 5 {
                words(&[word(&request, 0), 1, 0, 0, 0, 1])
            } else {
                success(
                    &request,
                    if index == 4 {
                        0
                    } else if procedure == 3 {
                        service_port as u32
                    } else {
                        1
                    },
                )
            };
            portmapper.send_to(&reply, client).unwrap();
        }
    });
    let mut peer = endpoint(&service);
    assert_eq!(
        unsafe {
            rpc::pmap_getport(
                (&mut peer as *mut libc::sockaddr_in).cast(),
                0x2000_0042,
                7,
                17,
            )
        },
        service_port
    );
    assert_eq!(peer.sin_port, 0, "pmap_getport must reset the caller port");
    let mut fd = -1;
    let pointer = unsafe {
        rpc::clntudp_create(
            (&mut peer as *mut libc::sockaddr_in).cast(),
            0x2000_0042,
            7,
            interval(20_000),
            &mut fd,
        )
    };
    assert!(!pointer.is_null());
    let client = Handle(pointer.cast());
    assert_eq!(u16::from_be(peer.sin_port), service_port);
    let service_worker = thread::spawn(move || {
        let mut request = [0u8; 128];
        let (length, from) = service.recv_from(&mut request).unwrap();
        assert_eq!(length, 44);
        service.send_to(&success(&request, 42), from).unwrap();
    });
    let mut value = 0;
    assert_eq!(invoke(&client, &mut 41, &mut value, 1_000_000), 0);
    assert_eq!(value, 42);
    assert_eq!(
        unsafe { rpc::pmap_set(0x2000_0042, 7, 17, service_port) },
        1
    );
    assert_eq!(unsafe { rpc::pmap_unset(0x2000_0042, 7) }, 1);
    assert_eq!(
        unsafe {
            rpc::pmap_getport(
                (&mut peer as *mut libc::sockaddr_in).cast(),
                0x2000_0042,
                7,
                17,
            )
        },
        0
    );
    assert_eq!(peer.sin_port, 0);
    let creation = unsafe { rpc::__rpc_thread_createerr() }.cast::<u8>();
    assert_eq!(unsafe { creation.cast::<c_int>().read() }, 15);
    let mut failed_fd = -1;
    assert!(
        unsafe {
            rpc::clntudp_create(
                (&mut peer as *mut libc::sockaddr_in).cast(),
                0x2000_0042,
                7,
                interval(20_000),
                &mut failed_fd,
            )
        }
        .is_null()
    );
    assert_eq!(failed_fd, -1);
    assert_eq!(unsafe { creation.cast::<c_int>().read() }, 14);
    assert_eq!(unsafe { creation.add(8).cast::<c_int>().read() }, 8);
    service_worker.join().unwrap();
    worker.join().unwrap();
}
