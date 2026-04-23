#![no_main]
//! Stateful fuzz target for FrankenLibC's POSIX socket surface:
//!
//!   socket, socketpair, bind, listen, accept, connect, send, recv,
//!   sendto, recvfrom, sendmsg, recvmsg, shutdown, setsockopt,
//!   getsockopt, getsockname, getpeername, accept4
//!
//! This is the classic network attack surface: kernel-ABI complexity
//! around sockaddrs, msghdrs, and the iovec family. The target keeps
//! a handle table of live sockets (with Live/Stale state), exercises
//! short operation sequences, and asserts the return-code contract
//! plus the stale-fd invariant (ops on a closed fd must return -1).
//!
//! Safety:
//! - All sockets are AF_UNIX with SOCK_STREAM or SOCK_DGRAM. We never
//!   open AF_INET/AF_INET6, so no real network traffic happens.
//! - Bind / connect addresses are in the abstract namespace
//!   (sun_path[0] = '\0', followed by a per-iteration unique name).
//!   No filesystem paths are created.
//! - Handle table capped at MAX_SOCKETS so libFuzzer can't exhaust
//!   the per-process fd limit.
//! - Send/recv buffers are fuzzer-sized but bounded to 1 KiB.
//! - Global SOCKLOCK serializes iterations.
//!
//! Bead: bd-dvr22 priority-3

use std::ffi::{c_int, c_void};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::socket_abi::{
    accept, accept4, bind, connect, getpeername, getsockname, getsockopt, listen, recv, recvfrom,
    send, sendto, setsockopt, shutdown, socket, socketpair,
};
use libfuzzer_sys::fuzz_target;

const MAX_SOCKETS: usize = 6;
const MAX_OPS: usize = 12;
const MAX_BUF: usize = 1024;

static SOCKLOCK: Mutex<()> = Mutex::new(());
static ADDR_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Arbitrary)]
enum Op {
    Socket { type_sel: u8 },
    Pair { type_sel: u8 },
    Bind { slot: u8 },
    Listen { slot: u8, backlog: i16 },
    Accept { slot: u8, use_accept4: bool, nonblock: bool },
    Connect { server_slot: u8, client_slot: u8 },
    Send { slot: u8, len: u16, flags_sel: u8 },
    Recv { slot: u8, len: u16, flags_sel: u8 },
    SendTo { slot: u8, len: u16, flags_sel: u8, dst_slot: u8 },
    RecvFrom { slot: u8, len: u16, flags_sel: u8 },
    Shutdown { slot: u8, how_sel: u8 },
    SetOpt { slot: u8, level_sel: u8, optname_sel: u8, value: i32 },
    GetOpt { slot: u8, level_sel: u8, optname_sel: u8 },
    GetName { slot: u8, peer: bool },
    MarkStale { slot: u8 },
}

#[derive(Debug, Arbitrary)]
struct SocketFuzzInput {
    ops: Vec<Op>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Live,
    Stale,
}

#[derive(Clone, Copy)]
struct Sock {
    fd: c_int,
    state: State,
    /// Bound abstract-namespace name (set only if Bind succeeded) so
    /// Connect can reference it.
    bound_name: Option<[u8; 16]>,
    is_stream: bool,
}

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: mode is set once, before any ABI call, from a
        // single thread under the OnceLock guard.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn pick_type(sel: u8) -> c_int {
    if sel & 1 == 0 {
        libc::SOCK_STREAM
    } else {
        libc::SOCK_DGRAM
    }
}

fn pick_how(sel: u8) -> c_int {
    match sel % 3 {
        0 => libc::SHUT_RD,
        1 => libc::SHUT_WR,
        _ => libc::SHUT_RDWR,
    }
}

fn pick_flags(sel: u8) -> c_int {
    // Safe flag set — never MSG_OOB (can disturb other test sockets
    // on the worker), never MSG_TRUNC which would need a dedicated
    // receiver discipline we don't have here.
    match sel % 4 {
        0 => 0,
        1 => libc::MSG_DONTWAIT,
        2 => libc::MSG_NOSIGNAL,
        _ => libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
    }
}

fn pick_setopt(level_sel: u8, optname_sel: u8) -> (c_int, c_int) {
    let level = match level_sel & 1 {
        0 => libc::SOL_SOCKET,
        _ => libc::IPPROTO_IP, // almost certainly EINVAL on AF_UNIX; that's fine
    };
    let optname = match optname_sel % 5 {
        0 => libc::SO_REUSEADDR,
        1 => libc::SO_KEEPALIVE,
        2 => libc::SO_SNDBUF,
        3 => libc::SO_RCVBUF,
        _ => libc::SO_BROADCAST,
    };
    (level, optname)
}

fn alloc_abstract_name() -> [u8; 16] {
    let mut name = [0u8; 16];
    let n = ADDR_COUNTER.fetch_add(1, Ordering::Relaxed);
    // Format: "\0flc-fuzz-<hex>"
    let bytes = format!("flc-fz-{:x}", n & 0xFFFFF);
    let pid = std::process::id();
    let _ = pid;
    name[0] = 0; // abstract-namespace sentinel
    let payload = bytes.as_bytes();
    let cap = name.len() - 1;
    let n = payload.len().min(cap);
    name[1..1 + n].copy_from_slice(&payload[..n]);
    name
}

fn make_sockaddr_un(name_payload: &[u8; 16]) -> (libc::sockaddr_un, u32) {
    // sockaddr_un.sun_path is [c_char; 108] on linux.
    let mut addr: libc::sockaddr_un = unsafe { MaybeUninit::zeroed().assume_init() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, &b) in name_payload.iter().enumerate() {
        if i >= addr.sun_path.len() {
            break;
        }
        addr.sun_path[i] = b as i8;
    }
    // addrlen = offsetof(sun_path) + length of the abstract name incl. leading NUL.
    let used = 1 + name_payload.iter().skip(1).position(|&b| b == 0).unwrap_or(15);
    let addrlen = (std::mem::size_of_val(&addr.sun_family) + used) as u32;
    (addr, addrlen)
}

fn assert_rc(rc: c_int, label: &'static str) {
    assert!(
        rc == 0 || rc == -1 || rc > 0,
        "{label}: rc {rc} out of socket-family contract"
    );
}

fn assert_signed(rc: isize, label: &'static str) {
    assert!(
        rc == -1 || rc >= 0,
        "{label}: rc {rc} out of sendrecv contract"
    );
}

fn pick_slot(table: &[Sock], slot: u8) -> Option<(usize, Sock)> {
    if table.is_empty() {
        return None;
    }
    let idx = (slot as usize) % table.len();
    Some((idx, table[idx]))
}

fn apply_op(op: &Op, table: &mut Vec<Sock>) {
    match op {
        Op::Socket { type_sel } => {
            if table.len() >= MAX_SOCKETS {
                return;
            }
            let t = pick_type(*type_sel);
            let fd = unsafe { socket(libc::AF_UNIX, t, 0) };
            assert_rc(fd, "socket");
            if fd >= 0 {
                table.push(Sock {
                    fd,
                    state: State::Live,
                    bound_name: None,
                    is_stream: t == libc::SOCK_STREAM,
                });
            }
        }
        Op::Pair { type_sel } => {
            if table.len() + 2 > MAX_SOCKETS {
                return;
            }
            let t = pick_type(*type_sel);
            let mut sv: [c_int; 2] = [-1, -1];
            let rc = unsafe { socketpair(libc::AF_UNIX, t, 0, sv.as_mut_ptr()) };
            assert_rc(rc, "socketpair");
            if rc == 0 {
                for &fd in &sv {
                    table.push(Sock {
                        fd,
                        state: State::Live,
                        bound_name: None,
                        is_stream: t == libc::SOCK_STREAM,
                    });
                }
            }
        }
        Op::Bind { slot } => {
            let Some((idx, mut s)) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale {
                return;
            }
            let name = alloc_abstract_name();
            let (addr, addrlen) = make_sockaddr_un(&name);
            let rc = unsafe {
                bind(
                    s.fd,
                    &addr as *const _ as *const libc::sockaddr,
                    addrlen,
                )
            };
            assert_rc(rc, "bind");
            if rc == 0 {
                s.bound_name = Some(name);
                table[idx] = s;
            }
        }
        Op::Listen { slot, backlog } => {
            let Some((_, s)) = pick_slot(table, *slot) else {
                return;
            };
            let rc = unsafe { listen(s.fd, (*backlog as c_int).clamp(0, 128)) };
            if s.state == State::Stale {
                assert_eq!(rc, -1, "listen on stale fd must fail");
                return;
            }
            assert_rc(rc, "listen");
        }
        Op::Accept { slot, use_accept4, nonblock } => {
            let Some((_, s)) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale || !s.is_stream {
                // Accept on non-stream or stale fd must fail.
                let rc = unsafe {
                    if *use_accept4 {
                        accept4(
                            s.fd,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            if *nonblock { libc::SOCK_NONBLOCK } else { 0 },
                        )
                    } else {
                        accept(s.fd, std::ptr::null_mut(), std::ptr::null_mut())
                    }
                };
                assert!(rc == -1, "accept on stale/non-stream must fail: rc={rc}");
                return;
            }
            // Accept is blocking; use MSG_DONTWAIT semantics by relying
            // on the socket having O_NONBLOCK via SOCK_NONBLOCK in
            // accept4. For plain accept, request with SO_NONBLOCK
            // fd flags — but we can't easily set that without fcntl,
            // so we skip plain accept on listening sockets and only
            // exercise the error path (accept4 with NONBLOCK returns
            // EAGAIN rather than hanging).
            if !*use_accept4 {
                return;
            }
            let rc = unsafe {
                accept4(
                    s.fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_NONBLOCK,
                )
            };
            assert_rc(rc, "accept4");
            if rc >= 0 && table.len() < MAX_SOCKETS {
                table.push(Sock {
                    fd: rc,
                    state: State::Live,
                    bound_name: None,
                    is_stream: true,
                });
            } else if rc >= 0 {
                // Above cap — close and drop.
                unsafe {
                    libc::close(rc);
                }
            }
        }
        Op::Connect { server_slot, client_slot } => {
            let Some((_, server)) = pick_slot(table, *server_slot) else {
                return;
            };
            let Some((_, client)) = pick_slot(table, *client_slot) else {
                return;
            };
            let Some(name) = server.bound_name else {
                return;
            };
            let (addr, addrlen) = make_sockaddr_un(&name);
            let rc = unsafe {
                connect(
                    client.fd,
                    &addr as *const _ as *const libc::sockaddr,
                    addrlen,
                )
            };
            // Could succeed, block (EINPROGRESS -> -1 EAGAIN under
            // nonblocking), or fail. The contract is rc in {0, -1}.
            assert_rc(rc, "connect");
        }
        Op::Send { slot, len, flags_sel } => {
            let Some((_, s)) = pick_slot(table, *slot) else {
                return;
            };
            let n = (*len as usize) % MAX_BUF;
            let buf = vec![0x5Au8; n];
            let rc = unsafe {
                send(
                    s.fd,
                    buf.as_ptr().cast::<c_void>(),
                    n,
                    pick_flags(*flags_sel) | libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            assert_signed(rc, "send");
            if s.state == State::Stale {
                assert_eq!(rc, -1, "send on stale fd must fail");
            }
        }
        Op::Recv { slot, len, flags_sel } => {
            let Some((_, s)) = pick_slot(table, *slot) else {
                return;
            };
            let n = (*len as usize) % MAX_BUF;
            let mut buf = vec![0u8; n];
            let rc = unsafe {
                recv(
                    s.fd,
                    buf.as_mut_ptr().cast::<c_void>(),
                    n,
                    pick_flags(*flags_sel) | libc::MSG_DONTWAIT,
                )
            };
            assert_signed(rc, "recv");
            if s.state == State::Stale {
                assert_eq!(rc, -1, "recv on stale fd must fail");
            }
        }
        Op::SendTo { slot, len, flags_sel, dst_slot } => {
            let Some((_, s)) = pick_slot(table, *slot) else {
                return;
            };
            let dst_name = pick_slot(table, *dst_slot).and_then(|(_, d)| d.bound_name);
            let n = (*len as usize) % MAX_BUF;
            let buf = vec![0x5Au8; n];
            let flags = pick_flags(*flags_sel) | libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL;
            let rc = if let Some(name) = dst_name {
                let (addr, addrlen) = make_sockaddr_un(&name);
                unsafe {
                    sendto(
                        s.fd,
                        buf.as_ptr().cast::<c_void>(),
                        n,
                        flags,
                        &addr as *const _ as *const libc::sockaddr,
                        addrlen,
                    )
                }
            } else {
                unsafe {
                    sendto(
                        s.fd,
                        buf.as_ptr().cast::<c_void>(),
                        n,
                        flags,
                        std::ptr::null(),
                        0,
                    )
                }
            };
            assert_signed(rc, "sendto");
        }
        Op::RecvFrom { slot, len, flags_sel } => {
            let Some((_, s)) = pick_slot(table, *slot) else {
                return;
            };
            let n = (*len as usize) % MAX_BUF;
            let mut buf = vec![0u8; n];
            let mut addr: MaybeUninit<libc::sockaddr_storage> = MaybeUninit::zeroed();
            let mut addrlen: u32 = std::mem::size_of::<libc::sockaddr_storage>() as u32;
            let rc = unsafe {
                recvfrom(
                    s.fd,
                    buf.as_mut_ptr().cast::<c_void>(),
                    n,
                    pick_flags(*flags_sel) | libc::MSG_DONTWAIT,
                    addr.as_mut_ptr() as *mut libc::sockaddr,
                    &mut addrlen,
                )
            };
            assert_signed(rc, "recvfrom");
        }
        Op::Shutdown { slot, how_sel } => {
            let Some((_, s)) = pick_slot(table, *slot) else {
                return;
            };
            let rc = unsafe { shutdown(s.fd, pick_how(*how_sel)) };
            if s.state == State::Stale {
                assert_eq!(rc, -1, "shutdown on stale fd must fail");
                return;
            }
            assert_rc(rc, "shutdown");
        }
        Op::SetOpt { slot, level_sel, optname_sel, value } => {
            let Some((_, s)) = pick_slot(table, *slot) else {
                return;
            };
            let (level, optname) = pick_setopt(*level_sel, *optname_sel);
            let v = *value;
            let rc = unsafe {
                setsockopt(
                    s.fd,
                    level,
                    optname,
                    &v as *const _ as *const c_void,
                    std::mem::size_of::<c_int>() as u32,
                )
            };
            assert_rc(rc, "setsockopt");
        }
        Op::GetOpt { slot, level_sel, optname_sel } => {
            let Some((_, s)) = pick_slot(table, *slot) else {
                return;
            };
            let (level, optname) = pick_setopt(*level_sel, *optname_sel);
            let mut v: c_int = 0;
            let mut optlen: u32 = std::mem::size_of::<c_int>() as u32;
            let rc = unsafe {
                getsockopt(
                    s.fd,
                    level,
                    optname,
                    &mut v as *mut _ as *mut c_void,
                    &mut optlen,
                )
            };
            assert_rc(rc, "getsockopt");
        }
        Op::GetName { slot, peer } => {
            let Some((_, s)) = pick_slot(table, *slot) else {
                return;
            };
            let mut addr: MaybeUninit<libc::sockaddr_storage> = MaybeUninit::zeroed();
            let mut addrlen: u32 = std::mem::size_of::<libc::sockaddr_storage>() as u32;
            let rc = unsafe {
                if *peer {
                    getpeername(
                        s.fd,
                        addr.as_mut_ptr() as *mut libc::sockaddr,
                        &mut addrlen,
                    )
                } else {
                    getsockname(
                        s.fd,
                        addr.as_mut_ptr() as *mut libc::sockaddr,
                        &mut addrlen,
                    )
                }
            };
            if s.state == State::Stale {
                assert_eq!(rc, -1, "get(sock|peer)name on stale fd must fail");
                return;
            }
            assert_rc(rc, if *peer { "getpeername" } else { "getsockname" });
        }
        Op::MarkStale { slot } => {
            let Some((idx, mut s)) = pick_slot(table, *slot) else {
                return;
            };
            if s.state == State::Stale {
                return;
            }
            // Close the fd so subsequent ops exercise the stale-fd path.
            // Then poison the slot's fd to a sentinel that the kernel
            // never returns (-1). Without this, a later `Socket` op can
            // reuse the just-closed fd number for a different slot, and
            // the stale slot's stored fd would now refer to that NEW
            // valid socket — the "stale shutdown must fail" assertion
            // then fails because shutdown succeeds on the reused fd.
            // This is the bd-yfsoc fuzz-harness fix.
            unsafe {
                libc::close(s.fd);
            }
            s.fd = -1;
            s.state = State::Stale;
            table[idx] = s;
        }
    }
}

fn cleanup(table: &mut Vec<Sock>) {
    for s in std::mem::take(table) {
        if s.state == State::Live {
            unsafe {
                libc::close(s.fd);
            }
        }
    }
}

fuzz_target!(|input: SocketFuzzInput| {
    if input.ops.len() > MAX_OPS {
        return;
    }
    init_hardened_mode();
    let _guard = SOCKLOCK.lock().unwrap_or_else(|p| p.into_inner());

    let mut table: Vec<Sock> = Vec::with_capacity(MAX_SOCKETS);
    for op in &input.ops {
        apply_op(op, &mut table);
    }
    cleanup(&mut table);
});
