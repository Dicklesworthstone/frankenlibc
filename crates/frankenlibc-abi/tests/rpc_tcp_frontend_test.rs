//! Exercise the exported constructors and the public LP64 CLIENT/AUTH prefixes.
//! The loopback peer constructs wire replies independently of FrankenLibC.
#![cfg(all(target_os = "linux", target_pointer_width = "64"))]

use frankenlibc_abi::rpc_abi::{self, Timeval};
use std::ffi::{c_char, c_int, c_void};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

type XdrProc = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
#[repr(C)]
struct Client {
    auth: *mut c_void,
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
        Timeval,
    ) -> c_int,
    abort: usize,
    geterr: unsafe extern "C" fn(*mut Client, *mut RpcError),
    freeres: usize,
    destroy: unsafe extern "C" fn(*mut Client),
    control: usize,
}
#[repr(C, align(8))]
struct RpcError {
    status: c_int,
    padding: u32,
    detail: [u8; 16],
}
#[repr(C)]
struct OpaqueAuth {
    flavor: c_int,
    base: *mut c_char,
    length: u32,
}
#[repr(C)]
struct Auth {
    credential: OpaqueAuth,
    verifier: OpaqueAuth,
    key: [u8; 8],
    ops: *const AuthOps,
    private: *mut c_void,
}
#[repr(C)]
struct AuthOps {
    next: usize,
    marshal: usize,
    validate: usize,
    refresh: usize,
    destroy: unsafe extern "C" fn(*mut Auth),
}
struct OwnedClient(*mut Client);
impl Drop for OwnedClient {
    fn drop(&mut self) {
        unsafe { ((*(*self.0).ops).destroy)(self.0) };
    }
}
struct OwnedAuth(*mut Auth);
impl Drop for OwnedAuth {
    fn drop(&mut self) {
        unsafe { ((*(*self.0).ops).destroy)(self.0) };
    }
}

fn endpoint() -> (TcpListener, libc::sockaddr_in) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    (
        listener,
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
        },
    )
}
fn accept(listener: TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "constructor did not connect");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn request(stream: &mut TcpStream) -> Vec<u8> {
    let mut record = Vec::new();
    for _ in 0..4096 {
        let mut marker = [0; 4];
        stream.read_exact(&mut marker).unwrap();
        let marker = u32::from_be_bytes(marker);
        let length = (marker & 0x7fff_ffff) as usize;
        assert!(length <= 1 << 20 && record.len() + length <= 1 << 20);
        let start = record.len();
        record.resize(start + length, 0);
        stream.read_exact(&mut record[start..]).unwrap();
        if marker & 0x8000_0000 != 0 {
            return record;
        }
    }
    panic!("excessive fragments");
}
fn reply(stream: &mut TcpStream, words: &[u32]) {
    let bytes = words
        .iter()
        .flat_map(|n| n.to_be_bytes())
        .collect::<Vec<_>>();
    // Split in the middle of an XDR word, with a fragmented record and split marker.
    let first = 7usize;
    stream
        .write_all(&(first as u32).to_be_bytes()[..2])
        .unwrap();
    stream
        .write_all(&(first as u32).to_be_bytes()[2..])
        .unwrap();
    stream.write_all(&bytes[..first]).unwrap();
    let last = 0x8000_0000 | (bytes.len() - first) as u32;
    stream.write_all(&last.to_be_bytes()).unwrap();
    stream.write_all(&bytes[first..]).unwrap();
}
unsafe extern "C" fn integer(xdr: *mut c_void, value: *mut c_void) -> c_int {
    unsafe { rpc_abi::xdr_u_int(xdr, value.cast()) }
}
fn call(client: &OwnedClient, result: &mut u32) -> c_int {
    let mut argument = 41u32;
    unsafe {
        ((*(*client.0).ops).call)(
            client.0,
            3,
            Some(integer),
            (&mut argument as *mut u32).cast(),
            Some(integer),
            (result as *mut u32).cast(),
            Timeval {
                tv_sec: 2,
                tv_usec: 0,
            },
        )
    }
}

#[test]
fn public_tcp_constructor_sends_auth_sys_and_decodes_fragmented_reply() {
    let (listener, mut address) = endpoint();
    let peer = std::thread::spawn(move || {
        let mut stream = accept(listener);
        let bytes = request(&mut stream);
        assert_eq!((word(&bytes, 4), word(&bytes, 8)), (0, 2));
        assert_eq!(
            (word(&bytes, 12), word(&bytes, 16), word(&bytes, 20)),
            (0x2000_0042, 7, 3)
        );
        assert_eq!((word(&bytes, 24), word(&bytes, 28)), (1, 28));
        let credential = &bytes[32..60];
        assert_eq!(word(credential, 4), 4);
        assert_eq!(&credential[8..12], b"node");
        assert_eq!((word(credential, 12), word(credential, 16)), (1001, 1002));
        assert_eq!((word(credential, 20), word(credential, 24)), (1, 42));
        assert_eq!(
            (word(&bytes, 60), word(&bytes, 64), word(&bytes, 68)),
            (0, 0, 41)
        );
        reply(&mut stream, &[word(&bytes, 0), 1, 0, 0, 0, 0, 42]);
    });
    let auth =
        unsafe { rpc_abi::authunix_create(c"node".as_ptr().cast_mut(), 1001, 1002, 1, &mut 42) };
    assert!(!auth.is_null());
    let auth = OwnedAuth(auth.cast());
    let mut fd = -1;
    let pointer = unsafe {
        rpc_abi::clnttcp_create(
            (&mut address as *mut libc::sockaddr_in).cast(),
            0x2000_0042,
            7,
            &mut fd,
            0,
            0,
        )
    };
    assert!(
        !pointer.is_null(),
        "public TCP constructor still rejects valid clients"
    );
    let client = OwnedClient(pointer.cast());
    assert!(fd >= 0);
    unsafe { (*client.0).auth = auth.0.cast() };
    let mut result = 0;
    assert_eq!(call(&client, &mut result), 0);
    assert_eq!(result, 42);
    drop(client);
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) },
        -1,
        "owned socket leaked"
    );
    assert_eq!(
        unsafe { (*auth.0).credential.flavor },
        1,
        "CLIENT destroyed caller AUTH"
    );
    peer.join().unwrap();
}

#[test]
fn public_tcp_borrowed_descriptor_preserves_flags_and_reports_version_range() {
    let (listener, mut address) = endpoint();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    stream.set_nonblocking(true).unwrap();
    let mut fd = stream.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let peer = std::thread::spawn(move || {
        let mut stream = accept(listener);
        let bytes = request(&mut stream);
        reply(&mut stream, &[word(&bytes, 0), 1, 0, 0, 0, 2, 10, 20]);
    });
    let pointer = unsafe {
        rpc_abi::clnttcp_create(
            (&mut address as *mut libc::sockaddr_in).cast(),
            0x2000_0042,
            7,
            &mut fd,
            0,
            0,
        )
    };
    assert!(!pointer.is_null());
    let client = OwnedClient(pointer.cast());
    let mut result = 0xdead_beef;
    assert_eq!(call(&client, &mut result), 9);
    assert_eq!(result, 0xdead_beef, "error reply invoked result callback");
    let mut error = RpcError {
        status: -1,
        padding: 0,
        detail: [0; 16],
    };
    unsafe { ((*(*client.0).ops).geterr)(client.0, &mut error) };
    assert_eq!(error.status, 9);
    assert_eq!(
        u64::from_ne_bytes(error.detail[..8].try_into().unwrap()),
        10
    );
    assert_eq!(
        u64::from_ne_bytes(error.detail[8..].try_into().unwrap()),
        20
    );
    drop(client);
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_GETFL) },
        flags,
        "borrowed fd closed or reconfigured"
    );
    peer.join().unwrap();
}
