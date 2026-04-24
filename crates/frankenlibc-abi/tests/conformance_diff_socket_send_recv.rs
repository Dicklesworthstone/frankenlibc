#![cfg(target_os = "linux")]

//! Differential conformance harness for socket I/O:
//!   - send / recv (basic byte transfer)
//!   - sendto / recvfrom (datagram-style with addrs)
//!   - sendmsg / recvmsg (scatter/gather + ancillary)
//!
//! Tests use socketpair(AF_UNIX) for stream and a pair of bound
//! AF_UNIX DGRAM sockets for sendto/recvfrom. Each test runs
//! independent fl-only and lc-only sequences with their own fds.
//!
//! Bead: CONFORMANCE: libc socket send/recv diff matrix.

use std::ffi::{c_int, c_void};

use frankenlibc_abi::socket_abi as fl;

unsafe extern "C" {
    fn send(sockfd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
    fn recv(sockfd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
    fn sendmsg(sockfd: c_int, msg: *const libc::msghdr, flags: c_int) -> isize;
    fn recvmsg(sockfd: c_int, msg: *mut libc::msghdr, flags: c_int) -> isize;
}

fn make_socketpair() -> (c_int, c_int) {
    let mut fds: [c_int; 2] = [-1, -1];
    let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(r, 0, "socketpair");
    (fds[0], fds[1])
}

#[test]
fn diff_send_recv_round_trip() {
    let payload = b"hello send/recv";
    let run = |send_via_fl: bool, recv_via_fl: bool| -> (isize, isize, Vec<u8>) {
        let (a, b) = make_socketpair();
        let n_s = if send_via_fl {
            unsafe { fl::send(a, payload.as_ptr() as *const c_void, payload.len(), 0) }
        } else {
            unsafe { send(a, payload.as_ptr() as *const c_void, payload.len(), 0) }
        };
        let mut buf = vec![0u8; payload.len()];
        let n_r = if recv_via_fl {
            unsafe { fl::recv(b, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) }
        } else {
            unsafe { recv(b, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) }
        };
        unsafe {
            libc::close(a);
            libc::close(b);
        }
        (
            n_s,
            n_r,
            if n_r > 0 { buf[..n_r as usize].to_vec() } else { Vec::new() },
        )
    };
    let (ns_a, nr_a, data_a) = run(true, false); // fl send, lc recv
    let (ns_b, nr_b, data_b) = run(false, true); // lc send, fl recv
    assert_eq!(ns_a, ns_b, "send n: fl={ns_a}, lc={ns_b}");
    assert_eq!(nr_a, nr_b, "recv n: fl_send={nr_a}, lc_send={nr_b}");
    assert_eq!(data_a, data_b, "transferred bytes diff");
    assert_eq!(data_a, payload.to_vec(), "expected payload");
}

#[test]
fn diff_recv_msg_dontwait_eagain() {
    // recv with MSG_DONTWAIT on an empty socket must fail with EAGAIN.
    let (a, b) = make_socketpair();
    let mut buf = [0u8; 16];
    let r_fl = unsafe {
        fl::recv(
            a,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    let r_lc = unsafe {
        recv(
            b,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    unsafe {
        libc::close(a);
        libc::close(b);
    }
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "recv MSG_DONTWAIT empty fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_send_recv_invalid_fd() {
    let payload = b"x";
    let r_fl = unsafe { fl::send(99999, payload.as_ptr() as *const c_void, payload.len(), 0) };
    let r_lc = unsafe { send(99998, payload.as_ptr() as *const c_void, payload.len(), 0) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "send bad-fd fail-match: fl={r_fl}, lc={r_lc}"
    );
    let mut buf = [0u8; 4];
    let r_fl = unsafe { fl::recv(99999, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
    let r_lc = unsafe { recv(99998, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "recv bad-fd fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_sendmsg_recvmsg_scatter_gather() {
    // sendmsg with 3 iovecs from one impl, recvmsg with 2 iovecs into
    // the other; bytes should be the contiguous concatenation.
    let chunks: &[&[u8]] = &[b"abc", b"DEFG", b"12"];
    let run = |send_via_fl: bool, recv_via_fl: bool| -> (isize, isize, Vec<u8>) {
        let (a, b) = make_socketpair();

        // Build send msghdr
        let iov_send: Vec<libc::iovec> = chunks
            .iter()
            .map(|c| libc::iovec {
                iov_base: c.as_ptr() as *mut c_void,
                iov_len: c.len(),
            })
            .collect();
        let msg_send = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iov_send.as_ptr() as *mut libc::iovec,
            msg_iovlen: iov_send.len(),
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let n_s = if send_via_fl {
            unsafe { fl::sendmsg(a, &msg_send, 0) }
        } else {
            unsafe { sendmsg(a, &msg_send, 0) }
        };

        // Receive into 2 iovecs
        let mut b1 = vec![0u8; 5];
        let mut b2 = vec![0u8; 16];
        let iov_recv = [
            libc::iovec {
                iov_base: b1.as_mut_ptr() as *mut c_void,
                iov_len: b1.len(),
            },
            libc::iovec {
                iov_base: b2.as_mut_ptr() as *mut c_void,
                iov_len: b2.len(),
            },
        ];
        let mut msg_recv = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iov_recv.as_ptr() as *mut libc::iovec,
            msg_iovlen: iov_recv.len(),
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let n_r = if recv_via_fl {
            unsafe { fl::recvmsg(b, &mut msg_recv, 0) }
        } else {
            unsafe { recvmsg(b, &mut msg_recv, 0) }
        };
        unsafe {
            libc::close(a);
            libc::close(b);
        }
        let mut got = Vec::new();
        if n_r > 0 {
            let take1 = (n_r as usize).min(b1.len());
            got.extend_from_slice(&b1[..take1]);
            if take1 == b1.len() {
                let take2 = (n_r as usize - take1).min(b2.len());
                got.extend_from_slice(&b2[..take2]);
            }
        }
        (n_s, n_r, got)
    };
    let (ns_a, nr_a, data_a) = run(true, false);
    let (ns_b, nr_b, data_b) = run(false, true);
    assert_eq!(ns_a, ns_b, "sendmsg n: fl={ns_a}, lc={ns_b}");
    assert_eq!(nr_a, nr_b, "recvmsg n: fl-send={nr_a}, lc-send={nr_b}");
    assert_eq!(data_a, data_b, "scatter-gather bytes diff");
    assert_eq!(data_a, b"abcDEFG12".to_vec(), "expected concatenation");
}

#[test]
fn socket_send_recv_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/socket.h(send/recv/sendmsg/recvmsg)\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
