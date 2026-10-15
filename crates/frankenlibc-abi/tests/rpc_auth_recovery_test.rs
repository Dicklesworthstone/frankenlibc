//! Public CLIENT/AUTH ABI recovery, with independent TCP and UDP wire peers.
#![cfg(all(target_os = "linux", target_pointer_width = "64"))]

use frankenlibc_abi::rpc_abi::{self, Timeval};
use std::ffi::{c_char, c_int, c_void};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

type Codec = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
#[repr(C)]
struct Client { auth: *mut Auth, ops: *const ClientOps, private: *mut c_void }
#[repr(C)]
struct ClientOps {
    call: unsafe extern "C" fn(*mut Client, u64, Option<Codec>, *mut c_void,
        Option<Codec>, *mut c_void, Timeval) -> c_int,
    abort: usize,
    geterr: unsafe extern "C" fn(*mut Client, *mut RpcError),
    freeres: usize,
    destroy: unsafe extern "C" fn(*mut Client),
    control: usize,
}
#[repr(C, align(8))]
struct RpcError { status: c_int, padding: u32, detail: [u8; 16] }
#[repr(C)]
struct OpaqueAuth { flavor: c_int, base: *mut c_char, length: u32 }
#[repr(C)]
struct Auth { credential: OpaqueAuth, verifier: OpaqueAuth, key: [u8; 8],
    ops: *const AuthOps, private: *mut c_void }
#[repr(C)]
struct AuthOps {
    next: unsafe extern "C" fn(*mut Auth),
    marshal: unsafe extern "C" fn(*mut Auth, *mut c_void) -> c_int,
    validate: unsafe extern "C" fn(*mut Auth, *mut OpaqueAuth) -> c_int,
    refresh: unsafe extern "C" fn(*mut Auth) -> c_int,
    destroy: unsafe extern "C" fn(*mut Auth),
}
struct OwnedClient(*mut Client);
impl Drop for OwnedClient {
    fn drop(&mut self) { unsafe { ((*(*self.0).ops).destroy)(self.0) }; }
}
struct OwnedAuth(*mut Auth);
impl Drop for OwnedAuth {
    fn drop(&mut self) { unsafe { ((*(*self.0).ops).destroy)(self.0) }; }
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|n| n.to_be_bytes()).collect()
}
fn address(endpoint: SocketAddr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: endpoint.port().to_be(),
        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) },
        sin_zero: [0; 8],
    }
}

enum Peer { Tcp(TcpStream), Udp(UdpSocket, Option<SocketAddr>) }
impl Peer {
    fn receive(&mut self) -> Option<Vec<u8>> {
        match self {
            Self::Tcp(stream) => {
                let mut marker = [0; 4];
                match stream.read_exact(&mut marker) {
                    Ok(()) => {}
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return None,
                    Err(e) => panic!("TCP marker: {e}"),
                }
                let marker = u32::from_be_bytes(marker);
                assert_ne!(marker & 0x8000_0000, 0);
                let count = (marker & 0x7fff_ffff) as usize;
                assert!(count <= 1 << 20);
                let mut payload = vec![0; count];
                stream.read_exact(&mut payload).unwrap();
                Some(payload)
            }
            Self::Udp(socket, sender) => {
                let mut bytes = [0; 4096];
                match socket.recv_from(&mut bytes) {
                    Ok((length, peer)) => { *sender = Some(peer); Some(bytes[..length].to_vec()) }
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut) => None,
                    Err(e) => panic!("UDP receive: {e}"),
                }
            }
        }
    }
    fn send(&mut self, payload: &[u8]) {
        match self {
            Self::Tcp(stream) => {
                let marker = 0x8000_0000 | payload.len() as u32;
                stream.write_all(&marker.to_be_bytes()).unwrap();
                stream.write_all(payload).unwrap();
            }
            Self::Udp(socket, sender) => {
                assert_eq!(socket.send_to(payload, sender.unwrap()).unwrap(), payload.len());
            }
        }
    }
    fn short_read_timeout(&self) {
        match self {
            Self::Tcp(stream) => stream.set_read_timeout(Some(Duration::from_millis(100))).unwrap(),
            Self::Udp(socket, _) => socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap(),
        }
    }
}
fn server(tcp: bool, run: impl FnOnce(Peer) + Send + 'static)
    -> (libc::sockaddr_in, std::thread::JoinHandle<()>) {
    if !tcp {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let addr = address(socket.local_addr().unwrap());
        return (addr, std::thread::spawn(move || run(Peer::Udp(socket, None))));
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = address(listener.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "no client connected");
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        run(Peer::Tcp(stream));
    });
    (addr, worker)
}
fn client(tcp: bool, peer: &mut libc::sockaddr_in, auth: *mut Auth) -> OwnedClient {
    let mut fd = -1;
    let pointer = unsafe {
        if tcp { rpc_abi::clnttcp_create((peer as *mut libc::sockaddr_in).cast(), 77, 1, &mut fd, 0, 0) }
        else { rpc_abi::clntudp_create((peer as *mut libc::sockaddr_in).cast(), 77, 1,
            Timeval { tv_sec: 2, tv_usec: 0 }, &mut fd) }
    }.cast::<Client>();
    assert!(!pointer.is_null());
    unsafe { (*pointer).auth = auth };
    OwnedClient(pointer)
}
unsafe extern "C" fn integer(xdr: *mut c_void, value: *mut c_void) -> c_int {
    unsafe { rpc_abi::xdr_u_int(xdr, value.cast()) }
}
fn call(client: &OwnedClient, micros: i64, output: &mut u32) -> c_int {
    let mut input = 41u32;
    unsafe { ((*(*client.0).ops).call)(client.0, 3, Some(integer),
        (&mut input as *mut u32).cast(), Some(integer), (output as *mut u32).cast(),
        Timeval { tv_sec: micros / 1_000_000, tv_usec: micros % 1_000_000 }) }
}
fn negotiated(tcp: bool) {
    let (mut endpoint, worker) = server(tcp, |mut peer| {
        let initial = peer.receive().expect("initial AUTH_SYS call");
        assert_eq!(word(&initial, 24), 1);
        let original = initial[32..32 + word(&initial, 28) as usize].to_vec();
        peer.send(&words(&[word(&initial, 0), 1, 0, 2, 12, 2, 3, 0x6162_6300, 0, 42]));
        let short = peer.receive().expect("second call must use nickname");
        assert_eq!(word(&short, 24), 2);
        assert_eq!(&short[32..35], b"abc");
        peer.send(&words(&[word(&short, 0), 1, 1, 1, 2]));
        let refreshed = peer.receive().expect("rejected nickname must retry original credentials");
        assert_ne!(word(&short, 0), word(&refreshed, 0));
        assert_eq!(word(&refreshed, 24), 1);
        let credential = &refreshed[32..32 + word(&refreshed, 28) as usize];
        assert_eq!(&credential[4..], &original[4..]); // stamp may advance
        peer.send(&words(&[word(&refreshed, 0), 1, 0, 0, 0, 0, 43]));
        let next = peer.receive().expect("ordinary call after recovery");
        assert_ne!(word(&next, 0), word(&refreshed, 0), "retry did not reserve its transaction ID");
        peer.send(&words(&[word(&next, 0), 1, 0, 0, 0, 0, 44]));
    });
    let pointer = unsafe { rpc_abi::authunix_create(c"node".as_ptr().cast_mut(), 1001,
        1002, 1, &mut 42) }.cast::<Auth>();
    assert!(!pointer.is_null());
    let auth = OwnedAuth(pointer);
    let client = client(tcp, &mut endpoint, auth.0);
    let mut output = 0;
    assert_eq!(call(&client, 2_000_000, &mut output), 0);
    assert_eq!(output, 42);
    assert_eq!(call(&client, 2_000_000, &mut output), 0);
    assert_eq!(output, 43);
    assert_eq!(call(&client, 2_000_000, &mut output), 0);
    assert_eq!(output, 44);
    assert_eq!(unsafe { (*auth.0).credential.flavor }, 1);
    drop(client);
    worker.join().unwrap();
}
#[test]
fn tcp_rejected_nickname_automatically_refreshes_original_credentials() { negotiated(true); }
#[test]
fn udp_rejected_nickname_automatically_refreshes_original_credentials() { negotiated(false); }

struct RefreshState { count: AtomicUsize, delay: Duration, permit: bool, valid: bool }
unsafe extern "C" fn noop(_: *mut Auth) {}
unsafe extern "C" fn marshal(_: *mut Auth, xdr: *mut c_void) -> c_int {
    let mut zero = 0;
    for _ in 0..4 {
        if unsafe { rpc_abi::xdr_u_int(xdr, &mut zero) } == 0 { return 0; }
    }
    1
}
unsafe extern "C" fn validate(auth: *mut Auth, _: *mut OpaqueAuth) -> c_int {
    i32::from(unsafe { &*(*auth).private.cast::<RefreshState>() }.valid)
}
unsafe extern "C" fn refresh(auth: *mut Auth) -> c_int {
    let state = unsafe { &*(*auth).private.cast::<RefreshState>() };
    state.count.fetch_add(1, Ordering::Relaxed);
    std::thread::sleep(state.delay);
    i32::from(state.permit)
}
static OPS: AuthOps = AuthOps { next: noop, marshal, validate, refresh, destroy: noop };
fn custom(state: &RefreshState) -> Auth {
    Auth { credential: OpaqueAuth { flavor: 0, base: std::ptr::null_mut(), length: 0 },
        verifier: OpaqueAuth { flavor: 0, base: std::ptr::null_mut(), length: 0 },
        key: [0; 8], ops: &OPS, private: (state as *const RefreshState).cast_mut().cast() }
}
fn state() -> RefreshState {
    RefreshState { count: AtomicUsize::new(0), delay: Duration::ZERO, permit: true, valid: true }
}

#[test]
fn repeated_credential_rejection_has_a_finite_retry_limit_on_both_transports() {
    for tcp in [false, true] {
        let state = state();
        let mut auth = custom(&state);
        let (mut endpoint, worker) = server(tcp, |mut peer| {
            let mut ids = Vec::new();
            for _ in 0..3 {
                let request = peer.receive().expect("bounded authentication attempt");
                let xid = word(&request, 0);
                assert!(!ids.contains(&xid));
                ids.push(xid);
                peer.send(&words(&[xid, 1, 1, 1, 2]));
            }
            peer.short_read_timeout();
            assert!(peer.receive().is_none(), "unbounded authentication retry");
        });
        let client = client(tcp, &mut endpoint, &mut auth);
        let mut output = 0xdead_beef;
        assert_eq!(call(&client, 2_000_000, &mut output), 7);
        assert_eq!(output, 0xdead_beef);
        assert_eq!(state.count.load(Ordering::Relaxed), 2);
        let mut error = RpcError { status: 0, padding: 0, detail: [0; 16] };
        unsafe { ((*(*client.0).ops).geterr)(client.0, &mut error) };
        assert_eq!(error.status, 7);
        assert_eq!(i32::from_ne_bytes(error.detail[..4].try_into().unwrap()), 2);
        drop(client);
        worker.join().unwrap();
    }
}

#[test]
fn rejected_refresh_and_unrelated_auth_errors_never_replay_the_call() {
    for tcp in [false, true] {
        for reason in [1, 2, 3, 4, 5, 7] {
            let mut state = state();
            state.permit = false;
            let mut auth = custom(&state);
            let (mut endpoint, worker) = server(tcp, move |mut peer| {
                let request = peer.receive().unwrap();
                peer.send(&words(&[word(&request, 0), 1, 1, 1, reason]));
                peer.short_read_timeout();
                assert!(peer.receive().is_none(), "an unrelated error replayed the call");
            });
            let client = client(tcp, &mut endpoint, &mut auth);
            let mut output = 123;
            assert_eq!(call(&client, 2_000_000, &mut output), 7);
            assert_eq!(output, 123);
            assert_eq!(state.count.load(Ordering::Relaxed), usize::from(reason == 2));
            drop(client);
            worker.join().unwrap();
        }
    }
}

#[test]
fn invalid_verifier_on_accepted_reply_never_refreshes_or_replays() {
    for tcp in [false, true] {
        let mut state = state();
        state.valid = false;
        let mut auth = custom(&state);
        let (mut endpoint, worker) = server(tcp, move |mut peer| {
            let request = peer.receive().unwrap();
            peer.send(&words(&[word(&request, 0), 1, 0, 0, 0, 0, 0, 999]));
            peer.short_read_timeout();
            assert!(peer.receive().is_none());
        });
        let client = client(tcp, &mut endpoint, &mut auth);
        let mut output = 123;
        assert_eq!(call(&client, 2_000_000, &mut output), 7);
        assert_eq!(output, 123);
        assert_eq!(state.count.load(Ordering::Relaxed), 0);
        drop(client);
        worker.join().unwrap();
    }
}

#[test]
fn refresh_callback_time_consumes_the_original_deadline() {
    for tcp in [false, true] {
        let mut state = state();
        state.delay = Duration::from_millis(500);
        let mut auth = custom(&state);
        let (mut endpoint, worker) = server(tcp, move |mut peer| {
            let request = peer.receive().unwrap();
            peer.send(&words(&[word(&request, 0), 1, 1, 1, 2]));
            // Longer than the callback: catch a send after an incorrectly renewed budget.
            match &peer {
                Peer::Tcp(stream) => stream.set_read_timeout(Some(Duration::from_millis(800))).unwrap(),
                Peer::Udp(socket, _) => socket.set_read_timeout(Some(Duration::from_millis(800))).unwrap(),
            }
            assert!(peer.receive().is_none(), "refresh renewed the call deadline");
        });
        let client = client(tcp, &mut endpoint, &mut auth);
        let mut output = 123;
        assert_eq!(call(&client, 250_000, &mut output), 5);
        assert_eq!(output, 123);
        assert_eq!(state.count.load(Ordering::Relaxed), 1);
        drop(client);
        worker.join().unwrap();
    }
}
