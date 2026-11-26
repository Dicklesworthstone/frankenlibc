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

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

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
    // Allocate the parent's state before spawning: all three owners must be
    // alive together. Addresses from exited workers may legitimately be reused.
    // SAFETY: this accessor returns the current thread's stable resolver state.
    let parent_address = unsafe { __res_state() } as usize;
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
    // Both workers retain their state while waiting at the second barrier.
    // Defer assertions until after releasing and joining them so a failure
    // cannot strand a live worker on the barrier.
    let overlapping_parent_address = unsafe { __res_state() } as usize;
    barrier.wait();
    let addresses: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_ne!(parent_address, 0);
    assert_eq!(overlapping_parent_address, parent_address);
    assert_eq!(unsafe { __res_state() } as usize, parent_address);
    assert_ne!(addresses[0], 0);
    assert_ne!(addresses[1], 0);
    assert_ne!(addresses[0], addresses[1]);
    assert!(!addresses.contains(&parent_address));
}

type Getaddrinfo = unsafe extern "C" fn(
    *const libc::c_char,
    *const libc::c_char,
    *const libc::addrinfo,
    *mut *mut libc::addrinfo,
) -> libc::c_int;
type Getnameinfo = unsafe extern "C" fn(
    *const libc::sockaddr,
    libc::socklen_t,
    *mut libc::c_char,
    libc::socklen_t,
    *mut libc::c_char,
    libc::socklen_t,
    libc::c_int,
) -> libc::c_int;

#[derive(Clone, Copy)]
struct HostApi {
    state: unsafe extern "C" fn() -> *mut c_void,
    init: unsafe extern "C" fn() -> libc::c_int,
    close: unsafe extern "C" fn(*mut c_void),
    select: unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> libc::c_int,
    lookup: Getaddrinfo,
    free: unsafe extern "C" fn(*mut libc::addrinfo),
    legacy: unsafe extern "C" fn(*const libc::c_char) -> *mut c_void,
    reverse: Getnameinfo,
}

fn host_apis() -> [HostApi; 2] {
    use frankenlibc_abi::{glibc_internal_abi as abi, resolv_abi as resolver};
    let native = HostApi {
        state: abi::__res_state,
        init: abi::__res_init,
        close: abi::__res_nclose,
        select: abi::__nss_configure_lookup,
        lookup: resolver::getaddrinfo,
        free: resolver::freeaddrinfo,
        legacy: resolver::gethostbyname,
        reverse: resolver::getnameinfo,
    };
    // SAFETY: each function type matches its public C declaration, and the
    // oracle helper rejects accidental binding to the candidate definition.
    let host = unsafe {
        HostApi {
            state: dlsym_oracle::host_fn(c"__res_state", native.state as *const ()),
            init: dlsym_oracle::host_fn(c"__res_init", native.init as *const ()),
            close: dlsym_oracle::host_fn(c"__res_nclose", native.close as *const ()),
            select: dlsym_oracle::host_fn(c"__nss_configure_lookup", native.select as *const ()),
            lookup: dlsym_oracle::host_fn(c"getaddrinfo", native.lookup as *const ()),
            free: dlsym_oracle::host_fn(c"freeaddrinfo", native.free as *const ()),
            legacy: dlsym_oracle::host_fn(c"gethostbyname", native.legacy as *const ()),
            reverse: dlsym_oracle::host_fn(c"getnameinfo", native.reverse as *const ()),
        }
    };
    [native, host]
}

/// Process-local NSS/environment changes never race unrelated test threads.
/// An unfixed candidate's fallback configuration is confined to loopback.
fn host_lookup_child(test: &str) -> bool {
    if std::env::var_os("FRANKENLIBC_GLOBAL_HOST_LOOKUP_CHILD").is_some() {
        return false;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("FRANKENLIBC_GLOBAL_HOST_LOOKUP_CHILD", "1")
        .env("FRANKENLIBC_RESOLV_CONF", "/dev/null")
        .env("FRANKENLIBC_NSSWITCH_CONF", "/dev/null")
        .env("FRANKENLIBC_HOSTS_PATH", "/dev/null")
        .env_remove("FRANKENLIBC_DNS_PORT")
        .env_remove("LOCALDOMAIN")
        .env_remove("RES_OPTIONS")
        .env_remove("HOSTALIASES")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "host lookup child timed out: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    true
}

struct ApiCleanup(*mut c_void, unsafe extern "C" fn(*mut c_void));
impl Drop for ApiCleanup {
    fn drop(&mut self) {
        // SAFETY: the selected provider owns this thread's still-live state.
        unsafe { (self.1)(self.0) };
    }
}

fn configure_host(api: HostApi, endpoint: SocketAddr) -> ApiCleanup {
    let SocketAddr::V4(endpoint) = endpoint else {
        panic!("IPv4 endpoint")
    };
    // SAFETY: operate only on this provider's current thread state. Initialize
    // its private extension before overriding documented public fields.
    unsafe {
        assert_eq!((api.select)(c"hosts".as_ptr(), c"dns".as_ptr()), 0);
        assert_eq!((api.init)(), 0);
        let pointer = (api.state)();
        let state = &mut *pointer.cast::<State>();
        state.options = RES_INIT | RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;
        state.retrans = 1;
        state.retry = 1;
        state.ndots_nsort = 1;
        state.dnsrch.fill(std::ptr::null_mut());
        state.nscount = 1;
        state.nsaddr_list[0].sin_family = libc::AF_INET as _;
        state.nsaddr_list[0].sin_port = endpoint.port().to_be();
        state.nsaddr_list[0].sin_addr.s_addr = u32::from_ne_bytes(endpoint.ip().octets());
        ApiCleanup(pointer, api.close)
    }
}

fn hostname_ipv4(api: HostApi, name: &std::ffi::CStr) -> Result<[u8; 4], libc::c_int> {
    // SAFETY: initialized hints/output, and a provider-matched deallocator.
    unsafe {
        let mut hints: libc::addrinfo = std::mem::zeroed();
        hints.ai_family = libc::AF_INET;
        hints.ai_socktype = libc::SOCK_STREAM;
        let mut result = std::ptr::null_mut();
        let status = (api.lookup)(name.as_ptr(), c"80".as_ptr(), &hints, &mut result);
        if status != 0 {
            assert!(result.is_null());
            return Err(status);
        }
        assert!(!result.is_null());
        assert_eq!((*result).ai_family, libc::AF_INET);
        let address = (*(*result).ai_addr.cast::<libc::sockaddr_in>())
            .sin_addr
            .s_addr;
        (api.free)(result);
        Ok(address.to_ne_bytes())
    }
}

fn host_reply(query: &[u8], code: u8, marker: u8) -> Vec<u8> {
    let message = DnsMessage::decode(query).unwrap();
    let kind = message.questions[0].qtype;
    let mut end = 12;
    while query[end] != 0 {
        end += usize::from(query[end]) + 1;
    }
    end += 5;
    let mut response = query[..end].to_vec();
    response[2] |= 0x80;
    response[3] = 0x80 | code;
    response[6..12].fill(0);
    if code == 0 {
        let data = match kind {
            1 => vec![203, 0, 113, marker],
            12 => frankenlibc_core::resolv::dns::encode_domain_name(b"reverse.caller.invalid")
                .unwrap(),
            _ => panic!("unexpected question type {kind}"),
        };
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 12]);
        response.extend_from_slice(&kind.to_be_bytes());
        response.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(&data);
    }
    response
}

struct HostServer {
    endpoint: SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: thread::JoinHandle<Vec<Vec<u8>>>,
}

impl HostServer {
    fn new(reply: impl Fn(&[u8]) -> Vec<u8> + Send + 'static) -> Self {
        let socket = udp();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let endpoint = socket.local_addr().unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(8);
            let mut seen = Vec::new();
            while !stopped.load(std::sync::atomic::Ordering::Acquire)
                && std::time::Instant::now() < deadline
            {
                let mut query = [0u8; 2048];
                match socket.recv_from(&mut query) {
                    Ok((n, peer)) => {
                        seen.push(
                            DnsMessage::decode(&query[..n]).unwrap().questions[0]
                                .qname
                                .clone(),
                        );
                        socket.send_to(&reply(&query[..n]), peer).unwrap();
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => panic!("DNS fixture receive: {error}"),
                }
            }
            seen
        });
        Self {
            endpoint,
            stop,
            worker,
        }
    }

    fn finish(self) -> Vec<Vec<u8>> {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        self.worker.join().unwrap()
    }
}

#[test]
fn global_host_lookup_observes_endpoint_changes_for_the_same_name() {
    if host_lookup_child("global_host_lookup_observes_endpoint_changes_for_the_same_name") {
        return;
    }
    for api in host_apis() {
        let first = HostServer::new(|query| host_reply(query, 0, 11));
        let cleanup = configure_host(api, first.endpoint);
        assert_eq!(
            hostname_ipv4(api, c"caller-state.invalid"),
            Ok([203, 0, 113, 11])
        );
        let second = HostServer::new(|query| host_reply(query, 0, 22));
        // SAFETY: mutate one already initialized state. No init/close/reset
        // occurs between lookups, so stale per-host caching cannot hide this.
        unsafe {
            (*cleanup.0.cast::<State>()).nsaddr_list[0].sin_port = second.endpoint.port().to_be()
        };
        assert_eq!(
            hostname_ipv4(api, c"caller-state.invalid"),
            Ok([203, 0, 113, 22])
        );
        assert!(!first.finish().is_empty());
        assert!(!second.finish().is_empty());
    }
}

#[test]
fn global_host_lookup_legacy_and_reverse_share_public_state() {
    if host_lookup_child("global_host_lookup_legacy_and_reverse_share_public_state") {
        return;
    }
    for api in host_apis() {
        let server = HostServer::new(|query| host_reply(query, 0, 77));
        let cleanup = configure_host(api, server.endpoint);
        // SAFETY: constant suffix and provider-owned hostent stay live while read.
        unsafe {
            (*cleanup.0.cast::<State>()).dnsrch[0] = c"caller.invalid".as_ptr().cast_mut();
            let entry = (api.legacy)(c"legacy-state".as_ptr()).cast::<libc::hostent>();
            assert!(!entry.is_null());
            assert_eq!((*entry).h_addrtype, libc::AF_INET);
            assert_eq!(
                std::slice::from_raw_parts((*(*entry).h_addr_list).cast::<u8>(), 4),
                [203, 0, 113, 77]
            );
            let address = libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: 80u16.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([203, 0, 113, 77]),
                },
                sin_zero: [0; 8],
            };
            let mut host = [0 as libc::c_char; 256];
            let mut service = [0 as libc::c_char; 16];
            assert_eq!(
                (api.reverse)(
                    (&address as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&address) as _,
                    host.as_mut_ptr(),
                    host.len() as _,
                    service.as_mut_ptr(),
                    service.len() as _,
                    libc::NI_NAMEREQD | libc::NI_NUMERICSERV,
                ),
                0
            );
            assert_eq!(
                std::ffi::CStr::from_ptr(host.as_ptr()).to_bytes(),
                b"reverse.caller.invalid"
            );
        }
        assert_eq!(
            server.finish(),
            [
                b"legacy-state.caller.invalid".to_vec(),
                b"77.113.0.203.in-addr.arpa".to_vec()
            ]
        );
    }
    for (index, api) in host_apis().into_iter().enumerate() {
        check_direct_dns_ptr_provider(api, index == 0);
    }
}

#[test]
fn global_host_lookup_search_options_match_gnu_query_order() {
    if host_lookup_child("global_host_lookup_search_options_match_gnu_query_order") {
        return;
    }
    use frankenlibc_abi::resolv_state::RES_NOTLDQUERY;
    type SearchCase<'a> = (libc::c_ulong, &'a [&'a std::ffi::CStr], &'a [&'a [u8]]);
    let cases: &[SearchCase<'_>] = &[
        (
            RES_DEFNAMES | RES_DNSRCH,
            &[c"first.invalid", c"second.invalid"],
            &[b"host.first.invalid", b"host.second.invalid", b"host"],
        ),
        (
            RES_DEFNAMES,
            &[c"first.invalid", c"second.invalid"],
            &[b"host.first.invalid", b"host"],
        ),
        (RES_DNSRCH, &[c"first.invalid"], &[b"host"]),
        (RES_NOTLDQUERY, &[c"first.invalid"], &[b"host"]),
        (
            RES_DEFNAMES | RES_DNSRCH | RES_NOTLDQUERY,
            &[c"first.invalid"],
            &[b"host.first.invalid"],
        ),
        (RES_DEFNAMES | RES_DNSRCH | RES_NOTLDQUERY, &[], &[b"host"]),
        (RES_DEFNAMES | RES_DNSRCH, &[c"."], &[b"host"]),
        (
            RES_DEFNAMES | RES_DNSRCH,
            &[c"", c"next.invalid"],
            &[b"host", b"host.next.invalid"],
        ),
        (
            RES_DEFNAMES | RES_DNSRCH | RES_NOTLDQUERY,
            &[c".", c"next.invalid"],
            &[b"host", b"host.next.invalid"],
        ),
    ];
    for api in host_apis() {
        for &(options, domains, expected) in cases {
            for code in [3, 2] {
                let server = HostServer::new(move |query| host_reply(query, code, 0));
                let cleanup = configure_host(api, server.endpoint);
                // SAFETY: constants outlive the call; no state borrow crosses I/O.
                unsafe {
                    let state = &mut *cleanup.0.cast::<State>();
                    state.options = RES_INIT | RES_RECURSE | options;
                    for (slot, domain) in state.dnsrch.iter_mut().zip(domains) {
                        *slot = domain.as_ptr().cast_mut();
                    }
                }
                assert_eq!(
                    hostname_ipv4(api, c"host"),
                    Err(if code == 3 {
                        libc::EAI_NONAME
                    } else {
                        libc::EAI_AGAIN
                    })
                );
                let seen = server.finish();
                assert_eq!(seen.iter().map(Vec::as_slice).collect::<Vec<_>>(), expected);
            }
        }
    }
}

#[test]
fn global_host_lookup_transport_and_dnssec_options_match_gnu() {
    if host_lookup_child("global_host_lookup_transport_and_dnssec_options_match_gnu") {
        return;
    }
    use frankenlibc_abi::resolv_state::{RES_USE_DNSSEC, RES_USEVC};
    use std::io::{Read, Write};
    for api in host_apis() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = listener.local_addr().unwrap();
        let udp_guard = UdpSocket::bind(endpoint).unwrap();
        udp_guard.set_nonblocking(true).unwrap();
        let cleanup = configure_host(api, endpoint);
        // SAFETY: documented public options in this thread's initialized state.
        unsafe {
            (*cleanup.0.cast::<State>()).options =
                RES_INIT | RES_USEVC | RES_USE_DNSSEC | RES_TRUSTAD
        };
        let worker = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(4);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "USEVC never opened TCP"
                        );
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("TCP fixture accept: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut length = [0; 2];
            stream.read_exact(&mut length).unwrap();
            let mut query = vec![0; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut query).unwrap();
            let message = DnsMessage::decode(&query).unwrap();
            assert_eq!(message.header.flags & 0x0120, 0x0020, "RD clear and AD set");
            assert_eq!(message.questions[0].qname, b"options.invalid");
            assert_eq!(message.additionals.len(), 1);
            assert_eq!(message.additionals[0].rtype, 41);
            assert_eq!(message.additionals[0].ttl & 0x8000, 0x8000, "DNSSEC DO bit");
            let reply = host_reply(&query, 0, 89);
            stream
                .write_all(&(reply.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&reply).unwrap();
        });
        assert_eq!(
            hostname_ipv4(api, c"options.invalid"),
            Ok([203, 0, 113, 89])
        );
        worker.join().unwrap();
        assert_eq!(
            udp_guard.recv(&mut [0; 512]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn global_host_lookup_ignores_tc_only_when_requested() {
    if host_lookup_child("global_host_lookup_ignores_tc_only_when_requested") {
        return;
    }
    use frankenlibc_abi::resolv_state::RES_IGNTC;
    for api in host_apis() {
        let server = HostServer::new(|query| {
            let mut response = host_reply(query, 0, 91);
            response[2] |= 0x02;
            response
        });
        let tcp_guard = std::net::TcpListener::bind(server.endpoint).unwrap();
        tcp_guard.set_nonblocking(true).unwrap();
        let cleanup = configure_host(api, server.endpoint);
        // SAFETY: the caller selects IGNORETC in its own initialized state.
        unsafe { (*cleanup.0.cast::<State>()).options |= RES_IGNTC };
        assert_eq!(
            hostname_ipv4(api, c"complete-tc.invalid"),
            Ok([203, 0, 113, 91])
        );
        assert!(!server.finish().is_empty());
        assert_eq!(
            tcp_guard.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn global_host_lookup_keeps_concurrent_thread_endpoints_isolated() {
    if host_lookup_child("global_host_lookup_keeps_concurrent_thread_endpoints_isolated") {
        return;
    }
    for api in host_apis() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let configure_lock = std::sync::Arc::new(std::sync::Mutex::new(()));
        let workers: Vec<_> = [31, 47]
            .into_iter()
            .map(|marker| {
                let barrier = barrier.clone();
                let configure_lock = configure_lock.clone();
                thread::spawn(move || {
                    let server = HostServer::new(move |query| host_reply(query, 0, marker));
                    // NSS backend selection is process-global. Serialize only that
                    // setup; both ordinary lookups run concurrently after the barrier.
                    let cleanup = {
                        let _guard = configure_lock.lock().unwrap();
                        configure_host(api, server.endpoint)
                    };
                    barrier.wait();
                    for _ in 0..2 {
                        assert_eq!(
                            hostname_ipv4(api, c"thread-state.invalid"),
                            Ok([203, 0, 113, marker])
                        );
                    }
                    let pointer = cleanup.0 as usize;
                    // A valid per-configuration cache may avoid the repeated query.
                    assert!(!server.finish().is_empty());
                    pointer
                })
            })
            .collect();
        let pointers: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_ne!(pointers[0], pointers[1]);
    }
}

#[test]
fn global_host_lookup_refreshes_files_and_environment_until_caller_override() {
    if host_lookup_child("global_host_lookup_refreshes_files_and_environment_until_caller_override")
    {
        return;
    }
    let api = host_apis()[0];
    let server = HostServer::new(|query| host_reply(query, 0, 63));
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-host-state-{}.conf",
        std::process::id()
    ));
    let write_config = |domain: &str| {
        std::fs::write(
            &path,
            format!("nameserver 127.0.0.1\nsearch {domain}\noptions timeout:1 attempts:1\n"),
        )
        .unwrap();
    };
    write_config("first.invalid");
    // SAFETY: this test is an isolated child. Its DNS worker never reads these
    // variables; no unrelated tests or resolver threads run in this process.
    unsafe {
        std::env::set_var("FRANKENLIBC_RESOLV_CONF", &path);
        std::env::set_var("FRANKENLIBC_DNS_PORT", server.endpoint.port().to_string());
        assert_eq!((api.select)(c"hosts".as_ptr(), c"dns".as_ptr()), 0);
        let pointer = (api.state)();
        (api.close)(pointer);
        *pointer.cast::<State>() = State::zeroed();
    }
    let pointer = unsafe { (api.state)() };
    let cleanup = ApiCleanup(pointer, api.close);
    assert_eq!(hostname_ipv4(api, c"refresh"), Ok([203, 0, 113, 63]));
    assert_ne!(unsafe { (*pointer.cast::<State>()).options & RES_INIT }, 0);
    write_config("second.invalid");
    assert_eq!(hostname_ipv4(api, c"refresh"), Ok([203, 0, 113, 63]));
    unsafe {
        std::env::set_var("LOCALDOMAIN", "environment.invalid");
        std::env::set_var("RES_OPTIONS", "ndots:2");
    }
    assert_eq!(hostname_ipv4(api, c"refresh"), Ok([203, 0, 113, 63]));
    assert_eq!(unsafe { (*pointer.cast::<State>()).ndots_nsort & 15 }, 2);
    assert_eq!(unsafe { (api.state)() }, pointer);

    let caller_domain = std::ffi::CString::new("caller.invalid").unwrap();
    unsafe {
        (*pointer.cast::<State>()).dnsrch[0] = caller_domain.as_ptr().cast_mut();
        (*pointer.cast::<State>()).dnsrch[1] = std::ptr::null_mut();
        std::env::remove_var("LOCALDOMAIN");
        std::env::remove_var("RES_OPTIONS");
    }
    write_config("must-not-replace-caller.invalid");
    assert_eq!(hostname_ipv4(api, c"refresh"), Ok([203, 0, 113, 63]));
    assert_eq!(
        unsafe { (*pointer.cast::<State>()).dnsrch[0] },
        caller_domain.as_ptr().cast_mut()
    );
    drop(cleanup);
    assert_eq!(
        caller_domain.as_bytes(),
        b"caller.invalid",
        "close must not own the caller suffix"
    );

    // Pointee edits also transfer control even when dnsrch's pointer remains
    // the original inline defdname address. Fresh initialization alone may
    // restore automatic refresh after the previous state is closed.
    write_config("original.invalid");
    unsafe { *pointer.cast::<State>() = State::zeroed() };
    let cleanup = ApiCleanup(pointer, api.close);
    assert_eq!(hostname_ipv4(api, c"refresh"), Ok([203, 0, 113, 63]));
    unsafe { *(*pointer.cast::<State>()).dnsrch[0] = b'x' as libc::c_char };
    write_config("must-not-replace-pointee.invalid");
    assert_eq!(hostname_ipv4(api, c"refresh"), Ok([203, 0, 113, 63]));
    assert_eq!(
        server.finish(),
        [
            b"refresh.first.invalid".to_vec(),
            b"refresh.second.invalid".to_vec(),
            b"refresh.environment.invalid".to_vec(),
            b"refresh.caller.invalid".to_vec(),
            b"refresh.original.invalid".to_vec(),
            b"refresh.xriginal.invalid".to_vec(),
        ]
    );
    drop(cleanup);

    // An implicitly initialized state with no-reload keeps its original
    // search suffix and search policy even after the file is replaced.
    let server = HostServer::new(|query| host_reply(query, 3, 0));
    std::fs::write(
        &path,
        b"nameserver 127.0.0.1\nsearch pinned.invalid\noptions no-reload attempts:1\n",
    )
    .unwrap();
    // SAFETY: isolated child. The previous state was closed and the DNS
    // worker does not read the process environment.
    unsafe {
        std::env::set_var("RES_OPTIONS", "no-tld-query");
        std::env::set_var("FRANKENLIBC_DNS_PORT", server.endpoint.port().to_string());
        *pointer.cast::<State>() = State::zeroed();
    }
    let _cleanup = ApiCleanup(pointer, api.close);
    assert_eq!(hostname_ipv4(api, c"missing"), Err(libc::EAI_NONAME));
    write_config("updated.invalid");
    unsafe { std::env::remove_var("RES_OPTIONS") };
    assert_eq!(hostname_ipv4(api, c"missing"), Err(libc::EAI_NONAME));

    // Explicit reentrant initialization takes a fresh snapshot. With the
    // option absent, the final absolute lookup of the bare name returns.
    let result = unsafe { frankenlibc_abi::glibc_internal_abi::__res_ninit(pointer) };
    assert_eq!(result, 0);
    assert_eq!(hostname_ipv4(api, c"missing"), Err(libc::EAI_NONAME));
    assert_eq!(
        server.finish(),
        [
            b"missing.pinned.invalid".to_vec(),
            b"missing.pinned.invalid".to_vec(),
            b"missing.updated.invalid".to_vec(),
            b"missing".to_vec(),
        ]
    );
}

#[test]
fn global_host_lookup_preserves_timing_selected_before_implicit_init() {
    if host_lookup_child("global_host_lookup_preserves_timing_selected_before_implicit_init") {
        return;
    }
    let api = host_apis()[0];
    let server = HostServer::new(|query| host_reply(query, 0, 64));
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-host-preinit-{}.conf",
        std::process::id()
    ));
    let write_config = |domain: &str| {
        // No explicit timing: the legacy initializer must retain caller values.
        std::fs::write(&path, format!("nameserver 127.0.0.1\nsearch {domain}\n")).unwrap();
    };
    write_config("first.invalid");
    // SAFETY: isolated child; the DNS worker never reads these variables.
    let pointer = unsafe {
        std::env::set_var("FRANKENLIBC_RESOLV_CONF", &path);
        std::env::set_var("FRANKENLIBC_DNS_PORT", server.endpoint.port().to_string());
        assert_eq!((api.select)(c"hosts".as_ptr(), c"dns".as_ptr()), 0);
        let pointer = (api.state)();
        (api.close)(pointer);
        let state = &mut *pointer.cast::<State>();
        *state = State::zeroed();
        state.retrans = 7;
        state.retry = 3;
        pointer
    };
    let _cleanup = ApiCleanup(pointer, api.close);
    for domain in ["first.invalid", "replacement.invalid"] {
        write_config(domain);
        assert_eq!(hostname_ipv4(api, c"preinit"), Ok([203, 0, 113, 64]));
        // SAFETY: current-thread state remains live and no I/O borrows it.
        let timing = unsafe {
            let state = &*pointer.cast::<State>();
            assert_ne!(state.options & RES_INIT, 0);
            (state.retrans, state.retry)
        };
        assert_eq!(timing, (7, 3));
    }
    let seen = server.finish();
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|owner| owner == b"preinit.first.invalid"));
}

#[test]
fn global_host_canonical_names_match_gnu_for_binary_cname_labels() {
    if host_lookup_child("global_host_canonical_names_match_gnu_for_binary_cname_labels") {
        return;
    }
    use frankenlibc_core::resolv::dns::encode_domain_name;
    let origin = c"origin.hostname.invalid.";
    let cases: Vec<(Vec<&[u8]>, &[u8])> = vec![
        (vec![], b"origin.hostname.invalid"),
        (vec![b"Canonical.test"], b"Canonical.test"),
        (vec![b"Middle.test", b"Final.test"], b"Final.test"),
        (vec![br"edge\.test"], b"origin.hostname.invalid"),
        (vec![br"zero.a\000b"], b"origin.hostname.invalid"),
        (vec![b"bad.x y"], b"origin.hostname.invalid"),
        (vec![b"-bad.test"], b"origin.hostname.invalid"),
        (vec![br"high.\255test"], b"origin.hostname.invalid"),
        (vec![b"Middle.test", br"edge\.test"], b"Middle.test"),
        (vec![br"edge\.test", b"Final.test"], b"Final.test"),
        (vec![b"good.-part"], b"good.-part"),
        (vec![b"good._part"], b"good._part"),
        (vec![b"."], b"."),
    ];
    for (targets, expected) in cases {
        let mut observations = Vec::new();
        for api in host_apis() {
            let valid_chain = targets.as_slice() == [b"Middle.test".as_slice(), b"Final.test".as_slice()];
            let targets: Vec<Vec<u8>> = targets.iter().map(|name| name.to_vec()).collect();
            let server = HostServer::new(move |query| {
                let message = DnsMessage::decode(query).unwrap();
                let kind = message.questions[0].qtype;
                assert_eq!(kind, 1);
                let mut response = host_reply(query, 3, 0);
                response[3] = 0x80;
                response[6..8].copy_from_slice(&((targets.len() + 1) as u16).to_be_bytes());
                let mut owner = vec![0xc0, 12];
                for target in &targets {
                    let target = encode_domain_name(target).unwrap();
                    response.extend_from_slice(&owner);
                    response.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 60]);
                    response.extend_from_slice(&(target.len() as u16).to_be_bytes());
                    response.extend_from_slice(&target);
                    owner = target;
                }
                // Address-owner case is not a new canonical-name decision.
                owner.make_ascii_uppercase();
                response.extend_from_slice(&owner);
                response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
                response
            });
            let _cleanup = configure_host(api, server.endpoint);
            // SAFETY: provider-specific state and deallocation, initialized
            // output, and results copied before another call reuses storage.
            unsafe {
                let mut hints: libc::addrinfo = std::mem::zeroed();
                hints.ai_family = libc::AF_INET;
                hints.ai_socktype = libc::SOCK_STREAM;
                hints.ai_flags = libc::AI_CANONNAME;
                let mut result = std::ptr::null_mut();
                assert_eq!(
                    (api.lookup)(origin.as_ptr(), c"80".as_ptr(), &hints, &mut result),
                    0
                );
                assert!(!result.is_null());
                assert!(!(*result).ai_canonname.is_null());
                let canonical = std::ffi::CStr::from_ptr((*result).ai_canonname)
                    .to_bytes()
                    .to_vec();
                assert!(!(*result).ai_addr.is_null());
                let address = (*(*result).ai_addr.cast::<libc::sockaddr_in>())
                    .sin_addr
                    .s_addr;
                assert_eq!(address.to_ne_bytes(), [192, 0, 2, 7]);
                (api.free)(result);

                let legacy = (api.legacy)(origin.as_ptr()).cast::<libc::hostent>();
                assert!(!legacy.is_null());
                assert!(!(*legacy).h_name.is_null());
                let legacy_name = std::ffi::CStr::from_ptr((*legacy).h_name)
                    .to_bytes()
                    .to_vec();
                assert_eq!((*legacy).h_length, 4);
                assert!(!(*legacy).h_addr_list.is_null());
                let first_address = (*(*legacy).h_addr_list).cast::<u8>();
                assert!(!first_address.is_null());
                assert_eq!(std::slice::from_raw_parts(first_address, 4), [192, 0, 2, 7]);
                if valid_chain {
                    let aliases = (*legacy).h_aliases;
                    assert!(!aliases.is_null());
                    assert!(!(*aliases).is_null());
                    assert_eq!(std::ffi::CStr::from_ptr(*aliases).to_bytes(), b"origin.hostname.invalid");
                    assert!(!(*aliases.add(1)).is_null());
                    assert_eq!(std::ffi::CStr::from_ptr(*aliases.add(1)).to_bytes(), b"Middle.test");
                    assert!((*aliases.add(2)).is_null());
                }
                observations.push((canonical, legacy_name));
            }
            assert!(
                !server.finish().is_empty(),
                "the lookup must execute a DNS exchange"
            );
        }
        assert_eq!(observations[0], observations[1], "targets={targets:?}");
        assert_eq!(observations[1], (expected.to_vec(), expected.to_vec()));
    }
    check_direct_dns_forward_provider(host_apis()[0]);
    check_direct_dns_negative_answers(host_apis()[0]);
    for (index, api) in host_apis().into_iter().enumerate() {
        check_direct_dns_tuple_provider(api, index == 0);
    }
}

fn check_direct_dns_ptr_provider(api: HostApi, candidate: bool) {
    use frankenlibc_abi::unistd_abi::{_nss_dns_gethostbyaddr_r, _nss_dns_gethostbyaddr2_r};

    type Reverse = unsafe extern "C" fn(
        *const c_void,
        libc::socklen_t,
        libc::c_int,
        *mut c_void,
        *mut libc::c_char,
        usize,
        *mut libc::c_int,
        *mut libc::c_int,
        *mut i32,
    ) -> libc::c_int;
    type Legacy = unsafe extern "C" fn(
        *const c_void,
        libc::socklen_t,
        libc::c_int,
        *mut c_void,
        *mut libc::c_char,
        usize,
        *mut libc::c_int,
        *mut libc::c_int,
    ) -> libc::c_int;
    let (reverse, legacy): (Reverse, Legacy) = if candidate {
        (_nss_dns_gethostbyaddr2_r, _nss_dns_gethostbyaddr_r)
    } else {
        // SAFETY: the direct GNU DNS providers have these same C signatures.
        unsafe {
            (
                dlsym_oracle::host_fn(c"_nss_dns_gethostbyaddr2_r", _nss_dns_gethostbyaddr2_r as *const ()),
                dlsym_oracle::host_fn(c"_nss_dns_gethostbyaddr_r", _nss_dns_gethostbyaddr_r as *const ()),
            )
        }
    };
    let server = HostServer::new(|query| host_reply(query, 0, 0));
    let _cleanup = configure_host(api, server.endpoint);
    // A direct provider call must bypass the process's normal hosts policy.
    assert_eq!(unsafe { (api.select)(c"hosts".as_ptr(), c"files".as_ptr()) }, 0);
    let ipv4 = [203u8, 0, 113, 77];
    let ipv6 = "2001:db8::77".parse::<std::net::Ipv6Addr>().unwrap().octets();
    let loopback = std::net::Ipv6Addr::LOCALHOST.octets();
    let mut compatible = [0u8; 16];
    compatible[12..].copy_from_slice(&ipv4);
    let mapped = std::net::Ipv4Addr::from(ipv4).to_ipv6_mapped().octets();
    for (af, input, family, address, ceiling) in [
        (libc::AF_INET, &ipv4[..], libc::AF_INET, &ipv4[..], i32::MAX),
        (libc::AF_INET6, &ipv6[..], libc::AF_INET6, &ipv6[..], 5),
        (libc::AF_INET6, &mapped[..], libc::AF_INET, &ipv4[..], -1),
        (libc::AF_INET6, &compatible[..], libc::AF_INET, &ipv4[..], 5),
        (libc::AF_INET6, &loopback[..], libc::AF_INET6, &loopback[..], i32::MAX),
    ] {
        let mut entry = std::mem::MaybeUninit::<libc::hostent>::uninit();
        let mut scratch = [0u8; 4096];
        let (mut error, mut host_error, mut ttl) = (0, -1, ceiling);
        // SAFETY: all caller objects are live. Read the hostent only on success.
        unsafe {
            let status = reverse(
                input.as_ptr().cast(), input.len() as _, af, entry.as_mut_ptr().cast(),
                scratch.as_mut_ptr().cast(), scratch.len(), &mut error, &mut host_error, &mut ttl,
            );
            let expected_ttl = (ceiling as u32).min(60) as i32;
            assert_eq!((status, host_error, ttl), (1, 0, expected_ttl));
            let entry = entry.assume_init();
            assert_eq!(std::ffi::CStr::from_ptr(entry.h_name).to_bytes(), b"reverse.caller.invalid");
            assert_eq!((entry.h_addrtype, entry.h_length), (family, address.len() as i32));
            assert!((*entry.h_aliases).is_null());
            assert_eq!(std::slice::from_raw_parts((*entry.h_addr_list).cast::<u8>(), address.len()), address);
            assert!((*entry.h_addr_list.add(1)).is_null());
        }
    }
    for (af, len, capacity, expected) in [
        (libc::AF_INET, 4, 1, (-2, libc::ERANGE, -1)),
        (libc::AF_INET, 3, 4096, (-1, libc::EAFNOSUPPORT, -1)),
        (libc::AF_INET6, 15, 4096, (-1, libc::EAFNOSUPPORT, -1)),
    ] {
        let mut scratch = [0xa5u8; 4096];
        let mut entry = std::mem::MaybeUninit::<libc::hostent>::uninit();
        let (mut error, mut host_error) = (0, 0);
        // SAFETY: input and output objects are live and cover their supplied lengths.
        let status = unsafe {
            legacy(
                ipv6.as_ptr().cast(), len, af, entry.as_mut_ptr().cast(),
                scratch.as_mut_ptr().cast(), capacity, &mut error, &mut host_error,
            )
        };
        assert_eq!((status, error, host_error), expected);
        if capacity == 1 {
            assert_eq!(scratch, [0xa5; 4096]);
        }
    }
    let queries = server.finish();
    assert_eq!(queries.len(), 5, "preflight failures must not issue PTR queries");
    assert_eq!(queries[0], b"77.113.0.203.in-addr.arpa");
    assert!(queries[1].ends_with(b".ip6.arpa"));
    assert_eq!(queries[2], queries[0]);
    assert_eq!(queries[3], queries[0]);
    assert!(queries[4].ends_with(b".ip6.arpa"));
}

fn dual_stack_reply(query: &[u8]) -> Vec<u8> {
    let kind = DnsMessage::decode(query).unwrap().questions[0].qtype;
    let mut response = host_reply(query, 3, 0);
    let address = match kind {
        1 => vec![192, 0, 2, 17],
        28 => std::net::Ipv6Addr::LOCALHOST.octets().to_vec(),
        _ => panic!("expected A or AAAA"),
    };
    response[3] = 0x80;
    response[7] = 1;
    response.extend_from_slice(&[0xc0, 12]);
    response.extend_from_slice(&kind.to_be_bytes());
    response.extend_from_slice(&[0, 1, 0, 0, 0, if kind == 1 { 19 } else { 31 }]);
    response.extend_from_slice(&(address.len() as u16).to_be_bytes());
    response.extend_from_slice(&address);
    response
}

fn check_direct_dns_forward_provider(api: HostApi) {
    use frankenlibc_abi::unistd_abi::_nss_dns_gethostbyname3_r;

    let server = HostServer::new(dual_stack_reply);
    let _cleanup = configure_host(api, server.endpoint);
    assert_eq!(unsafe { (api.select)(c"hosts".as_ptr(), c"files".as_ptr()) }, 0);
    for (family, expected, initial_ttl) in [
        (libc::AF_INET, vec![192u8, 0, 2, 17], -1),
        (libc::AF_INET6, std::net::Ipv6Addr::LOCALHOST.octets().to_vec(), 7),
    ] {
        let mut entry = std::mem::MaybeUninit::<libc::hostent>::uninit();
        let mut scratch = [0u8; 1024];
        let (mut error, mut host_error, mut ttl) = (0, -1, initial_ttl);
        let mut canon = std::ptr::null_mut();
        // SAFETY: the provider fills independent caller-owned objects. Read
        // the hostent and its nested pointers only after a successful return.
        unsafe {
            assert_eq!(
                _nss_dns_gethostbyname3_r(
                    c"forward.provider.invalid.".as_ptr(), family, entry.as_mut_ptr().cast(),
                    scratch.as_mut_ptr().cast(), scratch.len(), &mut error, &mut host_error,
                    &mut ttl, &mut canon,
                ),
                1
            );
            let entry = entry.assume_init();
            assert_eq!(entry.h_name, canon);
            assert!(!canon.is_null());
            assert_eq!(std::ffi::CStr::from_ptr(canon).to_bytes(), b"forward.provider.invalid");
            assert_eq!(entry.h_addrtype, family);
            assert_eq!(entry.h_length as usize, expected.len());
            assert_eq!(std::slice::from_raw_parts((*entry.h_addr_list).cast::<u8>(), expected.len()), expected);
            assert!((*entry.h_addr_list.add(1)).is_null());
            assert!((*entry.h_aliases).is_null());
            let record_ttl = if family == libc::AF_INET { 19 } else { 31 };
            assert_eq!((ttl, host_error), ((initial_ttl as u32).min(record_ttl) as i32, 0));
        }
    }
    assert_eq!(server.finish(), vec![b"forward.provider.invalid".to_vec(); 2]);
}

fn check_direct_dns_tuple_provider(api: HostApi, candidate: bool) {
    use frankenlibc_abi::unistd_abi::_nss_dns_gethostbyname4_r;
    use std::ffi::{CStr, c_char, c_int};

    #[repr(C)]
    struct Tuple {
        next: *mut Tuple,
        name: *mut c_char,
        family: c_int,
        addr: [u32; 4],
        scopeid: u32,
    }
    type Lookup = unsafe extern "C" fn(
        *const c_char, *mut *mut c_void, *mut c_char, usize,
        *mut c_int, *mut c_int, *mut i32,
    ) -> c_int;
    let lookup: Lookup = if candidate {
        _nss_dns_gethostbyname4_r
    } else {
        unsafe {
            dlsym_oracle::host_fn(
                c"_nss_dns_gethostbyname4_r", _nss_dns_gethostbyname4_r as *const (),
            )
        }
    };
    let server = HostServer::new(dual_stack_reply);
    let _cleanup = configure_host(api, server.endpoint);
    assert_eq!(unsafe { (api.select)(c"hosts".as_ptr(), c"files".as_ptr()) }, 0);
    let name = c"tuples.provider.invalid.";
    for supplied in [false, true] {
        let mut first = std::mem::MaybeUninit::<Tuple>::zeroed();
        let mut head: *mut c_void = if supplied { first.as_mut_ptr().cast() } else { std::ptr::null_mut() };
        let mut buffer = [0u8; 2048];
        let (mut error, mut host_error, mut ttl) = (0, 0, i32::MAX);
        // SAFETY: the head and scratch survive through inspection of every
        // returned tuple. No pointers are retained across resolver calls.
        unsafe {
            assert_eq!(lookup(name.as_ptr(), &mut head, buffer.as_mut_ptr().add(1).cast(),
                buffer.len() - 1, &mut error, &mut host_error, &mut ttl), 1);
            assert!(!head.is_null());
            if supplied {
                assert_eq!(head, first.as_mut_ptr().cast());
            }
            let first = &*head.cast::<Tuple>();
            assert!(!first.name.is_null());
            assert_eq!(CStr::from_ptr(first.name).to_bytes(), b"tuples.provider.invalid");
            assert!(!first.next.is_null());
            let second = &*first.next;
            assert!(second.next.is_null());
            let mut families = Vec::new();
            for item in [first, second] {
                families.push(item.family);
                let bytes = std::slice::from_raw_parts(item.addr.as_ptr().cast::<u8>(), 16);
                match item.family {
                    libc::AF_INET => assert_eq!(&bytes[..4], &[192, 0, 2, 17]),
                    libc::AF_INET6 => assert_eq!(bytes, std::net::Ipv6Addr::LOCALHOST.octets()),
                    other => panic!("unexpected address family {other}"),
                }
                assert_eq!(item.scopeid, 0);
            }
            families.sort_unstable();
            assert_eq!(families, [libc::AF_INET, libc::AF_INET6]);
            assert_eq!(ttl, 19);
        }
    }
    assert_eq!(server.finish(), vec![b"tuples.provider.invalid".to_vec(); 4]);
}

fn check_direct_dns_negative_answers(api: HostApi) {
    use frankenlibc_abi::unistd_abi::{
        _nss_dns_gethostbyaddr_r, _nss_dns_gethostbyname_r, _nss_dns_gethostbyname4_r,
    };
    let server = HostServer::new(|query| host_reply(query, 3, 0));
    let _cleanup = configure_host(api, server.endpoint);
    let mut entry = std::mem::MaybeUninit::<libc::hostent>::uninit();
    let mut buffer = [0u8; 4096];
    let name = c"absent.provider.invalid.";
    let address = [192u8, 0, 2, 18];
    let mut head = std::ptr::null_mut();
    for operation in 0..3 {
        let (mut error, mut host_error) = (0, 0);
        // SAFETY: each operation has valid caller-owned output and scratch
        // space, so its failure must come from the loopback server's NXDOMAIN.
        let status = unsafe {
            match operation {
                0 => _nss_dns_gethostbyname_r(
                    name.as_ptr(), entry.as_mut_ptr().cast(), buffer.as_mut_ptr().cast(),
                    buffer.len(), &mut error, &mut host_error,
                ),
                1 => _nss_dns_gethostbyname4_r(
                    name.as_ptr(), &mut head, buffer.as_mut_ptr().cast(), buffer.len(),
                    &mut error, &mut host_error, std::ptr::null_mut(),
                ),
                _ => _nss_dns_gethostbyaddr_r(
                    address.as_ptr().cast(), 4, libc::AF_INET, entry.as_mut_ptr().cast(),
                    buffer.as_mut_ptr().cast(), buffer.len(), &mut error, &mut host_error,
                ),
            }
        };
        assert_eq!((status, error, host_error), (0, libc::ENOENT, 1));
    }
    assert!(head.is_null());
    let queries = server.finish();
    assert!(queries.iter().filter(|q| q.as_slice() == b"absent.provider.invalid").count() >= 2);
    assert!(queries.iter().any(|q| q.as_slice() == b"18.2.0.192.in-addr.arpa"));
}

#[test]
fn ipv4_dns_answers_follow_public_sortlist_in_stable_order() {
    if host_lookup_child("ipv4_dns_answers_follow_public_sortlist_in_stable_order") {
        return;
    }
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-sortlist-{}.conf",
        std::process::id(),
    ));
    let mut file = std::fs::File::create_new(&path).unwrap();
    std::io::Write::write_all(
        &mut file,
        b"sortlist 172.16.0.0 192.0.2.0/255.255.255.128\noptions ndots:5\n",
    ).unwrap();
    drop(file);
    let native = host_apis()[0];
    // SAFETY: only this child changes its environment, before starting any
    // server threads. The initialized state belongs to this thread.
    unsafe {
        std::env::set_var("FRANKENLIBC_RESOLV_CONF", &path);
        assert_eq!((native.init)(), 0);
        let pointer = (native.state)();
        let state = &*pointer.cast::<State>();
        let fields = if cfg!(target_endian = "little") { 0x25 } else { 0x5200_0000 };
        assert_eq!(state.ndots_nsort, fields);
        assert_eq!(state.sort_list[0].addr.s_addr.to_ne_bytes(), [172, 16, 0, 0]);
        assert_eq!(state.sort_list[0].mask.to_ne_bytes(), [255, 255, 0, 0]);
        assert_eq!(state.sort_list[1].addr.s_addr.to_ne_bytes(), [192, 0, 2, 0]);
        assert_eq!(state.sort_list[1].mask.to_ne_bytes(), [255, 255, 255, 128]);
        (native.close)(pointer);
        std::env::set_var("FRANKENLIBC_RESOLV_CONF", "/dev/null");
    }
    std::fs::remove_file(path).unwrap();

    let wire = [
        [192u8, 0, 2, 99], [198, 51, 100, 7], [203, 0, 113, 8],
        [198, 51, 100, 3], [192, 0, 2, 11],
    ];
    for api in host_apis() {
        let server = HostServer::new(move |query| {
            let mut response = host_reply(query, 3, 0);
            response[3] = 0x80;
            response[7] = wire.len() as u8;
            for address in wire {
                response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                response.extend_from_slice(&address);
            }
            response
        });
        let _cleanup = configure_host(api, server.endpoint);
        for (prefix, order) in [
            (None, [0, 1, 2, 3, 4]),
            (Some([198u8, 51, 100, 0]), [1, 3, 0, 2, 4]),
            (Some([192, 0, 2, 0]), [0, 4, 1, 2, 3]),
        ] {
            // SAFETY: this child owns the provider's initialized thread state.
            // No reference to it survives the lookup. Copy each address while
            // the provider still owns the same successful hostent result.
            unsafe {
                let state = &mut *(api.state)().cast::<State>();
                let count = u32::from(prefix.is_some());
                state.ndots_nsort = if cfg!(target_endian = "little") {
                    1 | (count << 4)
                } else {
                    (1 << 28) | (count << 24)
                };
                if let Some(network) = prefix {
                    state.sort_list[0].addr.s_addr = u32::from_ne_bytes(network);
                    state.sort_list[0].mask = u32::from_ne_bytes([255, 255, 255, 0]);
                }
                let host = (api.legacy)(c"sorted.example.invalid.".as_ptr()).cast::<libc::hostent>();
                assert!(!host.is_null());
                assert_eq!(((*host).h_addrtype, (*host).h_length), (libc::AF_INET, 4));
                assert!(!(*host).h_addr_list.is_null());
                for (position, index) in order.into_iter().enumerate() {
                    let address = *(*host).h_addr_list.add(position);
                    assert!(!address.is_null());
                    assert_eq!(*address.cast::<[u8; 4]>(), wire[index]);
                }
                assert!((*(*host).h_addr_list.add(wire.len())).is_null());
            }
        }
        assert_eq!(server.finish().len(), 3);
    }
}
